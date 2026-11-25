"""Launch an installed Chromium extension for browser acceptance checks."""


def installed_page(playwright, extension, profile, *, headless=True, host_resolver_rules=None):
    """Return the context and verifier page; close the context if startup fails.

    The caller owns a successfully opened context and must close it after use.
    """
    args = [
        f"--disable-extensions-except={extension}",
        f"--load-extension={extension}",
    ]
    if host_resolver_rules is not None:
        args.append("--host-resolver-rules=" + host_resolver_rules)
    context = playwright.chromium.launch_persistent_context(
        profile,
        channel="chromium",
        headless=headless,
        args=args,
    )
    try:
        worker = (
            context.service_workers[0]
            if context.service_workers
            else context.wait_for_event("serviceworker")
        )
        page = context.new_page()
        page.goto("chrome-extension://" + worker.url.split("/")[2] + "/index.html")
        return context, page
    except Exception:
        context.close()
        raise
