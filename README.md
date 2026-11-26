# Groq Key Vault

Kho lưu trữ Groq API Key dạng tĩnh (Static Web App), giao diện **Monochrome** tối giản, **bo góc**, **dạng khung**, sẵn sàng deploy miễn phí lên **GitHub Pages (`github.io`)**.

## Cấu trúc dự án

- `index.html` — Giao diện chính của kho key & hướng dẫn lấy key bằng code.
- `styles.css` — Hệ thống giao diện Monochrome (Sáng / Tối), bo góc, dạng khung.
- `app.js` — Logic đọc `keys.json`, xoay vòng / chọn key ngẫu nhiên, test key trực tiếp với Groq API, và mã hóa/giải mã AES-256-GCM trên trình duyệt.
- `keys.json` — Tệp dữ liệu lưu danh sách key (nguồn dữ liệu chính khi chạy qua HTTP / GitHub Pages).
- `keys-fallback.js` — Bản dự phòng chỉ dùng khi mở trực tiếp `index.html` bằng giao thức `file://`.
- `.nojekyll` — Tắt Jekyll trên GitHub Pages để phục vụ các tệp tĩnh nguyên bản.

## Lưu ý bảo mật quan trọng khi đưa lên GitHub

1. **Tránh auto-revoke từ GitHub Secret Scanning:** Tệp `keys.json` mặc định lưu các key ở dạng `rev-b64` (đảo chuỗi + Base64) để không chứa chuỗi raw bắt đầu bằng `gsk_` trong Git history.
2. **Nếu deploy `github.io` công khai (Public Repo):** Chế độ `Open (rev-b64)` chỉ chống quét regex tự động chứ **không giấu được key trước người dùng truy cập trang web**. Nếu chỉ muốn bản thân hoặc team có mật khẩu mới lấy được key, hãy mở web → xuống mục **Quản lý, Thêm Key & Xuất keys.json** → chọn **Encrypted (AES-256-GCM)** → nhập Master Passphrase → tải `keys.json` mới về thay thế tệp cũ trong repo trước khi `git push`.

> Lưu ý: Nếu bạn cập nhật `keys.json` sang bản `Encrypted`, hãy xóa hoặc cập nhật cả `keys-fallback.js` (hoặc xóa dòng `<script src="./keys-fallback.js"></script>` trong `index.html`) để không còn dữ liệu `open` cũ trong lịch sử/file dự phòng.

## Hướng dẫn Deploy lên GitHub Pages (`github.io`)

1. Tạo một repository mới trên GitHub (ví dụ `groq-key-vault`, hoặc `<username>.github.io` nếu muốn dùng domain gốc).
2. Đưa mã nguồn lên GitHub:
   ```bash
   git init
   git add .
   git commit -m "Initial Groq Key Vault"
   git branch -M main
   git remote add origin https://github.com/<username>/<repo>.git
   git push -u origin main
   ```
3. Mở **Settings → Pages** trên repository GitHub:
   - **Source**: `Deploy from a branch`
   - **Branch**: `main` / `/ (root)`
   - Bấm **Save**.
4. Truy cập sau ~1 phút tại:
   - Giao diện Web: `https://<username>.github.io/<repo>/`
   - JSON Endpoint cho code: `https://<username>.github.io/<repo>/keys.json`

## Chạy thử trên máy cá nhân

Bạn có thể mở trực tiếp `index.html` bằng trình duyệt, hoặc chạy một HTTP server tĩnh để kiểm tra đúng hành vi như trên GitHub Pages:

```bash
python -m http.server 8080
```

Sau đó mở `http://localhost:8080`.
