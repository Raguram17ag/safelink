# app/html_parser.py

from bs4 import BeautifulSoup

def extract_html_features(html: str):
    """
    Extracts structured information from HTML content.
    Returns a dictionary with:
      - title
      - meta_description
      - meta_keywords
      - links
      - forms
      - scripts
      - images
      - iframes
      - clean_text
    """

    soup = BeautifulSoup(html, "html.parser")

    # Title
    title = soup.title.string.strip() if soup.title and soup.title.string else None

    # Meta tags
    meta_desc = None
    meta_keywords = None
    for tag in soup.find_all("meta"):
        if tag.get("name") == "description":
            meta_desc = tag.get("content", None)
        elif tag.get("name") == "keywords":
            meta_keywords = tag.get("content", None)

    # Links
    links = [a.get("href") for a in soup.find_all("a", href=True)]

    # Forms (method + action)
    # inside your forms loop in extract_html_features
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        has_password = False
        for i in form.find_all("input"):
            t = (i.get("type") or "text").lower()
            n = i.get("name", "").lower()
            inputs.append({"type": t, "name": n, "placeholder": i.get("placeholder")})
            if t == "password" or "password" in n:
                has_password = True
        forms.append({
            "method": form.get("method", "GET").upper(),
            "action": form.get("action", ""),
            "inputs": inputs,
            "has_password": has_password
        })

    # Scripts
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]

    # Images
    images = [img.get("src") for img in soup.find_all("img") if img.get("src")]

    # Iframes
    iframes = [iframe.get("src") for iframe in soup.find_all("iframe") if iframe.get("src")]

    # Clean text (remove scripts/styles and extract text)
    for tag in soup(["script", "style"]):
        tag.decompose()

    clean_text = soup.get_text(separator=" ", strip=True)

    return {
        "title": title,
        "meta_description": meta_desc,
        "meta_keywords": meta_keywords,
        "links": links,
        "forms": forms,
        "scripts": scripts,
        "images": images,
        "iframes": iframes,
        "clean_text": clean_text[:2000]  # limit for safety
    }
