import subprocess
from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()


@app.post("/clone")
def clone(repo_url: str):
    subprocess.run(f"git clone {repo_url}", shell=True, check=False)
    return {"ok": True}


@app.get("/files/{name}")
def get_file(name: str):
    return FileResponse(f"/data/{name}")


@app.get("/health")
def health():
    return {"status": "ok"}
