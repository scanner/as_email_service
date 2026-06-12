from django.contrib.staticfiles.storage import ManifestStaticFilesStorage


class RelaxedManifestStaticFilesStorage(ManifestStaticFilesStorage):
    """ManifestStaticFilesStorage with manifest_strict=False and resilient manifest loading.

    WHY manifest_strict=False:
    The strict default (True since Django 4.1) raises ValueError for any
    {% static %} call whose file is absent from staticfiles.json, producing
    an immediate 500. That "fail fast" behaviour is desirable in a pure
    production deploy, but we run the same image in two modes:

      - Production image (make build, no volume mounts): collectstatic runs
        during `docker build`, every referenced file is in the manifest, and
        manifest_strict=True would never trigger anyway.

      - Dev/integration image (make build-dev, ./app volume-mounted): the
        volume mount replaces /app at container start, discarding the
        staticfiles/ directory that the image build created. Running
        collectstatic manually before every `DEBUG=False` test session is
        impractical.

    WHY this is acceptable for this app:
    All JS and CSS referenced via {% static %} tags are bundled into the
    Docker image at build time. A file can only be absent from the manifest
    in the dev-image scenario above, where a developer is intentionally
    bypassing the normal build process. In that case falling back to the
    unhashed URL (no cache-busting for that file) is a reasonable trade-off:
    the app stays functional, and the developer knows they are not in a
    fully production-equivalent environment.

    In a genuine production deploy the manifest will always be complete, so
    this flag has zero practical effect there.

    WHY load_manifest is overridden:
    The base class raises ValueError for a malformed or unrecognised-version
    staticfiles.json (e.g. invalid JSON from an interrupted collectstatic, or
    a file left behind from a different Django version). That exception
    propagates during template rendering — specifically inside {% static %}
    calls — and because the template renders {% static %} in the <head>
    (favicons, importmap) well before the {% csrf_token %} tag in the <body>,
    the exception prevents the CSRF cookie from ever being set. The browser
    then logs "Forbidden (CSRF cookie not set.)" for every subsequent POST.

    By catching ValueError here and returning an empty manifest instead, we
    ensure {% static %} always succeeds (falling back to unhashed URLs) and
    the CSRF cookie is always set regardless of the manifest file's state.
    """

    manifest_strict = False

    def load_manifest(self):
        try:
            return super().load_manifest()
        except ValueError:
            # Malformed or unrecognised-version staticfiles.json: treat as
            # missing so {% static %} falls back to unhashed URLs rather than
            # crashing before {% csrf_token %} is rendered.
            return {}, ""

    def stored_name(self, name):
        # base.html uses {% static '/favicon.ico' %} and similar leading-slash
        # paths to produce root-relative URLs that bypass the STATIC_URL
        # prefix (browsers expect favicons at /, not /static/). These keys are
        # never in the manifest (which stores only relative paths). The parent
        # stored_name() falls back to hashing the file via
        # safe_join(STATIC_ROOT, name), which raises SuspiciousFileOperation
        # for any name starting with '/' because the resolved path escapes
        # STATIC_ROOT. Django converts SuspiciousFileOperation → 400.
        # Return the name unchanged so _url() passes it to StaticFilesStorage
        # which handles leading-slash paths correctly via urljoin().
        if name.startswith("/"):
            return name
        return super().stored_name(name)
