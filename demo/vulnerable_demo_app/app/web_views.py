import html


def greeting_page(request):
    name = request.args.get("name", "guest")
    return "<html><body><h1>Hello " + name + "</h1></body></html>"


def search_results_page(request, results):
    term = request.args.get("q", "")
    items = "".join(f"<li>{r['title']}</li>" for r in results)
    return f"<html><body><p>Results for {term}</p><ul>{items}</ul></body></html>"


def greeting_page_safe(request):
    name = html.escape(request.args.get("name", "guest"))
    return "<html><body><h1>Hello " + name + "</h1></body></html>"


def redirect_after_login(request):
    target = request.args.get("next", "/")
    return {"status": 302, "headers": {"Location": target}}


def health_check():
    return {"status": "ok"}
