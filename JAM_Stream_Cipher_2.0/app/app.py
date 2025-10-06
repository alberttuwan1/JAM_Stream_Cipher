# app.py
from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import StreamingResponse, JSONResponse
import io
import jamstream

app = FastAPI(title="JamstreamaCipher API")

@app.post("/encrypt-file")
async def encrypt_file(file: UploadFile, key: str = Form(...)):
    try:
        data = await file.read()
        encrypted_data = jamstreama.encrypt(data, key)

        output_filename = file.filename + ".enc"
        return StreamingResponse(
            io.BytesIO(encrypted_data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={output_filename}"}
        )
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/decrypt-file")
async def decrypt_file(file: UploadFile, key: str = Form(...)):
    try:
        data = await file.read()
        decrypted_data = jamstreama.decrypt(data, key)

        output_filename = file.filename.replace(".enc", "") or "decrypted_file"
        return StreamingResponse(
            io.BytesIO(decrypted_data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={output_filename}"}
        )
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
