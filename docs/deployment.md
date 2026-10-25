# Deployment guide

The repository is prepared for a split deployment: the React/Vite frontend can run on Vercel or Netlify, while the FastAPI backend can run on Render or another Python service. No live deployment was performed in this workspace, so no public URL is claimed.

## Backend on Render

1. Create a Render Web Service connected to the repository.
2. Choose Python 3.11+.
3. Set the build command to `pip install -r requirements.txt`.
4. Set the start command to `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`.
5. Set `GHOSTTRACE_ALLOWED_ORIGINS` to the deployed frontend origin, for example `https://your-app.example`.
6. Set `GHOSTTRACE_ROOT` only if the dataset is mounted at a different path. The default repository root is preferred.
7. Configure the health check path as `/api/health`.

The current job manager and output file are process-local. On an ephemeral service, jobs and generated output can disappear on restart or redeploy. For a public deployment with real workloads, replace the in-memory job manager and local output with a persistent database/object store and a durable worker queue before accepting uploads.

## Frontend on Vercel or Netlify

1. Import the repository and set the project root to `frontend`.
2. Build with `npm run build` and publish the `frontend/dist` directory.
3. Set `VITE_API_BASE_URL` to the deployed backend origin, without a trailing slash.
4. Add the final frontend origin to the backend’s `GHOSTTRACE_ALLOWED_ORIGINS` value.
5. Trigger a production build and check `/api/health` through the browser UI.

## Local production-style check

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
Set-Location frontend
npm run build
npm run preview -- --host 127.0.0.1 --port 4173
```

The public demo should use synthetic data. The challenge dataset is not automatically suitable for public hosting or screenshots; review its publication permissions before deployment.
