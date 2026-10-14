# DP-Advice hosted demo

The GitHub Pages frontend is generated at `posts/dp-advisor.html` from
`web/templates/index.html`. To rebuild it after changing the UI:

```sh
python3 dp-advice-api/build_pages.py --api-base https://dp-advice-api.onrender.com
```

The Python API is deployed from `render.yaml` as a separate Render web service.
The service only installs the packages needed by the public API; submitted
Python is statically analyzed and is never executed. Browser-session budgets
and logs are held in bounded, temporary in-memory state and reset when the
service restarts or the session expires. This demo state is not a durable
compliance ledger.

Deploy in two pushes so the public page does not appear before its API exists:

1. Commit and push `render.yaml` and `dp-advice-api/` to `main`.
2. In Render, create a Blueprint from `ravikm-phd/ravikm-phd.github.io` and
   apply the `render.yaml` service. Wait for
   `https://dp-advice-api.onrender.com/healthz` to return `{"status":"ok"}`.
3. From the website repository root, run
   `python3 dp-advice-api/build_pages.py --api-base https://dp-advice-api.onrender.com`.
   Commit and push `posts/dp-advisor.html` and `posts/dp-advisor-assets/`.
   GitHub Pages will then serve the app at
   `https://privability.works/posts/dp-advisor.html`.
