# KubeSentinel site (static, Vercel-ready)
No build step. `index.html` + optional `data/replay.json`.
Deploy: push this folder to GitHub, then Vercel > Add New Project > import it (Framework: Other). Or: `npx vercel --prod` inside this folder.
Real data: `python3 scripts/export_replay.py ~/kubesentinel/data/benchmark_raw.json`, commit `data/replay.json`.
Security note: this site never connects to your cluster. Do not expose the detector API to the internet.
