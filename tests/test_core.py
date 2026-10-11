import fake200 as f


def R(status, body, ok=True, error=None):
    d = {"ok": ok, "status": status, "body": body, "url": ""}
    if error:
        d["error"] = error
    return d


def test_normalize_strips_digits_and_whitespace():
    assert f.normalize("Abc 123\n x456y") == "abc # x#y"


def test_similarity_identical_and_disjoint():
    a = f.normalize("<p>lorem ipsum dolor sit amet</p>" * 50)
    assert f.similarity(a, a) == 1.0
    assert f.similarity("aaaa", "bbbb") < 0.3


def test_rand_path_shape_and_uniqueness():
    p1, p2 = f.rand_path(), f.rand_path()
    assert p1.startswith("/f2k-") and p1 != p2


def test_title_extraction_trims_whitespace():
    assert f.title_of("<html><title> Hello World </title></html>") == "Hello World"


def test_vendor_on_target_and_baseline_is_fake200():
    block = "<html><title>Attention Required!</title>__cf_chl_opt script</html>"
    r = f.classify(R(200, block), [R(200, block), R(200, block)])
    assert r["verdict"] == "FAKE200"
    assert r["vendor"] == "cloudflare"


def test_baseline_same_page_high_sim_is_fake200():
    body = "<html><title>Site</title>" + "<p>lorem ipsum dolor sit amet</p>" * 200 + "</html>"
    r = f.classify(R(200, body), [R(200, body)])
    assert r["verdict"] == "FAKE200" and r["sim"] >= 0.9


def test_soft404_shared_template_is_suspect():
    prefix = "<html><title>Shop</title><div class=menu>home about contact cart</div><main>" + "x" * 3000
    target = R(200, prefix + "product " * 100)
    baseline = R(200, prefix + "sorry " * 140)
    r = f.classify(target, [baseline])
    assert r["verdict"] == "SUSPECT"


def test_real_page_with_404_baselines_is_ok():
    page = "<html><title>Login</title><form>user pass</form></html>"
    r = f.classify(R(200, page), [R(404, "nope"), R(404, "gone")])
    assert r["verdict"] == "OK"


def test_vendor_keyword_on_target_only_is_suspect():
    page = "<html><body>we use akamai cdn for speed</body></html>"
    r = f.classify(R(200, page), [R(404, "404 not found")])
    assert r["verdict"] == "SUSPECT" and r["vendor"] == "akamai"


def test_generic_keyword_without_vendor_is_suspect():
    page = "<html><div>please enter the captcha to continue</div></html>"
    r = f.classify(R(200, page), [R(404, "nope")])
    assert r["verdict"] == "SUSPECT"


def test_non200_is_skipped_and_error_is_error():
    assert f.classify(R(403, "x"), [])["verdict"] == "SKIP"
    r = f.classify(R(None, "", ok=False, error="ConnectTimeout"), [])
    assert r["verdict"] == "ERROR"
