#!/usr/bin/env bash
#
# Run SpamAssassin training pipeline:
#   1. Stage spam/ham messages from the training inbox
#   2. Update SA rules if available
#   3. Train on any staged spam/ham
#   4. Restart spamassassin only if rules were updated
#
# See docs/sa-training.md for full details.
#
set -euo pipefail

########################################################################
#
# Step 1: Run the sa-training management command to stage messages.
#
echo "==> Running sa-training to stage messages..."
output=$(docker compose run --rm sa-training 2>&1)
echo "$output"

# Parse the "Processed: N spam, N ham, ..." line from the output.
# Uses sed instead of grep -P for macOS (BSD grep) compatibility.
#
spam_count=$(echo "$output" | sed -n 's/.*Processed: \([0-9]*\) spam.*/\1/p')
ham_count=$(echo "$output" | sed -n 's/.*Processed: [0-9]* spam, \([0-9]*\) ham.*/\1/p')
spam_count=${spam_count:-0}
ham_count=${ham_count:-0}

if [ "$spam_count" -eq 0 ] && [ "$ham_count" -eq 0 ]; then
    echo "==> No spam or ham messages to process. Done."
    exit 0
fi

echo "==> Staged ${spam_count} spam and ${ham_count} ham messages."

########################################################################
#
# Step 2: Check for SA rule updates.
#
rules_updated=0
echo "==> Checking for SpamAssassin rule updates..."
if docker compose exec spamassassin sa-update --checkonly; then
    echo "==> No rule updates available."
else
    # sa-update --checkonly exits non-zero when updates ARE available.
    echo "==> Rule updates available, downloading..."
    if docker compose exec spamassassin sa-update; then
        echo "==> Rules updated."
        rules_updated=1
    else
        rc=$?
        # sa-update exit code 1 means updates were available and applied.
        # Exit code 0 means no updates. Other codes are errors.
        if [ "$rc" -eq 1 ]; then
            echo "==> Rules updated (exit code 1 = updates applied)."
            rules_updated=1
        else
            echo "WARNING: sa-update exited with code $rc"
        fi
    fi
fi

########################################################################
#
# Step 3: Train on staged spam and ham.
#
if [ "$spam_count" -gt 0 ]; then
    echo "==> Training on ${spam_count} spam messages..."
    docker compose exec spamassassin sa-learn --spam /mnt/training/spam/
fi

if [ "$ham_count" -gt 0 ]; then
    echo "==> Training on ${ham_count} ham messages..."
    docker compose exec spamassassin sa-learn --ham /mnt/training/ham/
fi

echo "==> Syncing Bayes database..."
docker compose exec spamassassin sa-learn --sync

########################################################################
#
# Step 4: Restart spamassassin only if rules were updated.
# NOTE: sa-learn updates the Bayes database which spamd reads dynamically,
# so no restart is needed after training. Only rule file changes from
# sa-update require a restart.
#
if [ "$rules_updated" -eq 1 ]; then
    echo "==> Restarting spamassassin to load new rules..."
    docker compose restart spamassassin
fi

echo "==> Done."
