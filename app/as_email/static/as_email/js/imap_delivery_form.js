// ImapDeliveryForm component
//
// Renders editable fields for an ImapDelivery delivery method.
// Does NOT talk to the API — it only emits field changes up to
// DeliveryMethodForm, which owns the save/delete logic.
//
// Fields:
//   imap_host             (string)
//   imap_port             (integer, default 993)
//   auth_type             ("password" | "oauth2"; oauth2 is a future placeholder)
//   username              (string, visible when auth_type == "password")
//   password              (string, visible when auth_type == "password")
//   autofile_spam         (boolean)
//   spam_score_threshold  (integer, visible when autofile_spam is true)
//
// Password masking
// ----------------
// The API intentionally never returns the stored password — credentials are
// write-only and stored encrypted at rest. This is standard practice: the
// server accepts a password on create/update but never sends it back.
// Submitting a PATCH without a password field leaves the stored value
// unchanged (see ImapDeliverySerializer.update()).
//
// Because the password is never returned, formData.password is always empty
// when an existing record is loaded. To avoid misleading the user into
// thinking no password is set, we show a masked placeholder (••••••••)
// whenever username is non-empty and the user has not yet started editing
// the password field.
//
// passwordEditing tracks whether the user has focused the password input.
// While false and a username is present, passwordMasked is true and the
// field displays the mask. On focus the mask is cleared so the user can
// type a replacement. On blur without typing, passwordEditing resets and
// the mask is restored, indicating no change will be sent on save.
//
// Test Connection
// ---------------
// The "Test Connection" button is enabled when imap_host, imap_port,
// username, and password are all non-empty — i.e. the user has typed a
// password value. For existing records the password is never returned by
// the API, so the button is inactive until the user types a new password.
//
// Clicking "Test Connection" POSTs to {deliveryMethodsUrl}test_imap/ and
// displays the result inline. The same check also runs automatically during
// save() in DeliveryMethodForm whenever password is non-empty.
//
import { ref, computed } from "vue";

export default {
  name: "ImapDeliveryForm",
  delimiters: ["[[", "]]"],

  props: {
    formData: { type: Object, required: true },
    errors: { type: Object, default: () => ({}) },
    // Collection URL (e.g. /as_email/api/v1/email_accounts/1/delivery_methods/)
    // used to build the test_imap endpoint URL.
    deliveryMethodsUrl: { type: String, default: "" },
  },

  emits: ["update:field"],

  setup(props, ctx) {
    const update = (field, value) => ctx.emit("update:field", field, value);

    const isPasswordAuth = computed(
      () => props.formData.auth_type === "password",
    );
    const isOAuthAuth = computed(() => props.formData.auth_type === "oauth2");

    // True while the user has the password field focused or has typed into it.
    //
    const passwordEditing = ref(false);

    // Controls whether the password is shown as plain text or obscured.
    //
    const showPassword = ref(false);

    // True when we should display the mask instead of the (empty) field value.
    //
    const passwordMasked = computed(
      () =>
        !passwordEditing.value &&
        !!props.formData.username &&
        !props.formData.password,
    );

    // The value bound to the password <input>. Shows a mask when passwordMasked
    // is true, otherwise the actual (possibly still-empty) formData value.
    //
    const passwordDisplayValue = computed(() =>
      passwordMasked.value ? "••••••••" : props.formData.password,
    );

    const onPasswordFocus = () => {
      passwordEditing.value = true;
    };

    // If the user focused but left without typing, restore the mask so it is
    // clear that the existing password will be kept unchanged on save.
    //
    const onPasswordBlur = (e) => {
      if (!e.target.value) {
        passwordEditing.value = false;
      }
    };

    // Test Connection state.
    //
    const testing = ref(false);
    const testResult = ref(null); // null | { success: bool, message: string }

    // Enabled only when all connection fields and a password value are present.
    // formData.password is empty for saved records (API never returns it), so
    // this naturally stays inactive until the user types a new password.
    //
    const canTest = computed(
      () =>
        !!props.formData.imap_host &&
        !!props.formData.imap_port &&
        !!props.formData.username &&
        !!props.formData.password,
    );

    const testConnection = async () => {
      if (!canTest.value || testing.value) return;
      testing.value = true;
      testResult.value = null;
      try {
        const res = await fetch(props.deliveryMethodsUrl + "test_imap/", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            imap_host: props.formData.imap_host,
            imap_port: props.formData.imap_port,
            username: props.formData.username,
            password: props.formData.password,
          }),
        });
        let body;
        try {
          body = await res.json();
        } catch {
          body = {
            success: false,
            message: `HTTP ${res.status}: ${res.statusText}`,
          };
        }
        testResult.value = {
          success: body.success ?? res.ok,
          message:
            body.message ??
            (res.ok ? "Connection successful." : "Connection failed."),
        };
      } catch (err) {
        testResult.value = {
          success: false,
          message: `Request failed: ${err}`,
        };
      } finally {
        testing.value = false;
      }
    };

    return {
      update,
      isPasswordAuth,
      isOAuthAuth,
      showPassword,
      passwordMasked,
      passwordDisplayValue,
      onPasswordFocus,
      onPasswordBlur,
      testing,
      testResult,
      canTest,
      testConnection,
    };
  },

  template: "#template-imap-delivery-form",
};
