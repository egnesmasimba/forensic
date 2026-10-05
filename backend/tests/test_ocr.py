from test_api import make_client


def test_image_text_is_scored_and_searchable(tmp_path, monkeypatch):
    def fake_recognize(path, language):
        assert path
        if language == "spa":
            return "cuenta 20418", 91.2
        if language == "eng":
            return "account 20418", 80.0
        from fastapi import HTTPException
        raise HTTPException(422, "Choose a supported OCR language")

    monkeypatch.setattr("app.routers.ocr.recognize", fake_recognize)
    with make_client(tmp_path) as client:
        case_id = client.post("/api/cases", json={"title": "Image review", "case_type": "Other"}).json()["id"]
        image = client.post(f"/api/cases/{case_id}/attachments", files={"file": ("page.png", b"image-bytes", "image/png")})
        assert image.status_code == 201
        attachment_id = image.json()["id"]
        text_file = client.post(f"/api/cases/{case_id}/attachments", files={"file": ("notes.txt", b"plain", "text/plain")})
        assert client.post(f"/api/ocr/attachments/{text_file.json()['id']}").status_code == 422
        assert client.post(f"/api/ocr/attachments/{attachment_id}?language=zz").status_code == 422

        read = client.post(f"/api/ocr/attachments/{attachment_id}?language=spa")
        assert read.status_code == 201
        assert read.json()["engine"] == "tesseract"
        assert read.json()["confidence"] == 91.2
        assert read.json()["text"] == "cuenta 20418"
        detail = client.get(f"/api/cases/{case_id}").json()
        stored = next(item for item in detail["attachments"] if item["id"] == attachment_id)
        assert stored["ocr_language"] == "spa"
        assert stored["ocr_confidence"] == 91.2

        found = client.get("/api/ocr/search", params={"q": "cuenta"})
        assert found.status_code == 200
        assert found.json()[0]["case_id"] == case_id
        assert "cuenta 20418" in found.json()[0]["snippet"]

        replaced = client.post(f"/api/ocr/attachments/{attachment_id}?language=eng")
        assert replaced.json()["text"] == "account 20418"
        assert client.get("/api/ocr/search", params={"q": "cuenta"}).json() == []
        assert len(client.get("/api/ocr/search", params={"q": "account"}).json()) == 1
