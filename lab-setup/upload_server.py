#!/usr/bin/env python3
"""
Simulates a document indexing web service.
Accepts file uploads and extracts metadata using libextractor.
Represents: document management systems, file sharing platforms, CMS backends.
"""
import http.server, cgi, subprocess, os, tempfile

class UploadHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"""<!DOCTYPE html><html><body>
        <h2>Document Indexing Service</h2>
        <p>Upload a document to extract and index its metadata.</p>
        <form method="POST" enctype="multipart/form-data" action="/upload">
        <input type="file" name="document"><br><br>
        <input type="submit" value="Upload & Index">
        </form></body></html>""")

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers["Content-Type"])
        pdict["boundary"] = pdict["boundary"].encode()
        fields = cgi.parse_multipart(self.rfile, pdict)

        filedata = fields["document"][0]
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".doc")
        tmp.write(filedata)
        tmp.close()

        # Extract metadata using libextractor (vulnerable path)
        # ulimit -s simulates container/systemd stack limits
        try:
            result = subprocess.run(
                ["bash", "-c", f"ulimit -s 2048; /usr/local/bin/extract_server {tmp.name}"],
                capture_output=True, text=True, timeout=10)
            output = result.stdout
            retcode = result.returncode
        except subprocess.TimeoutExpired:
            output = "Timeout"
            retcode = -1
        except Exception as e:
            output = str(e)
            retcode = -1

        os.unlink(tmp.name)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        resp = f"Received: {len(filedata)} bytes\nExtractor exit: {retcode}\nMetadata:\n{output}"
        self.wfile.write(resp.encode())

if __name__ == "__main__":
    print("Document Indexing Service running on :8080")
    print("Using libextractor for metadata extraction")
    http.server.HTTPServer(("0.0.0.0", 8080), UploadHandler).serve_forever()
