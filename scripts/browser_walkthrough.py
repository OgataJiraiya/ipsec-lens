"""Optional Selenium/Chromium release check; operates only on local loopback UI."""
import json
import argparse
import shutil
from selenium.webdriver.chrome.service import Service
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument("--live",action="store_true")
ARGS=parser.parse_args()
OUT=ROOT/("runtime/browser-live" if ARGS.live else "runtime/browser")
OUT.mkdir(parents=True,exist_ok=True)
options=Options()
options.binary_location=shutil.which("chromium")
for arg in ("--headless=new","--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--window-size=1366,768"):
    options.add_argument(arg)
options.add_experimental_option("prefs",{"download.default_directory":str(OUT),"download.prompt_for_download":False})
options.set_capability("goog:loggingPrefs",{"browser":"ALL"})
driver=webdriver.Chrome(service=Service(shutil.which("chromedriver")),options=options)
wait=WebDriverWait(driver,20)
results=[]
uploaded={}

def resize(width,height):
    driver.set_window_size(width,height)
    inner=driver.execute_script("return [window.innerWidth,window.innerHeight]")
    driver.set_window_size(width+(width-inner[0]),height+(height-inner[1]))


def click_nav(name):
    driver.find_element(By.XPATH,f"//nav/button[.//span[text()='{name}']]").click()
    wait.until(EC.text_to_be_present_in_element((By.TAG_NAME,"h1"),name))


def text():
    return driver.find_element(By.TAG_NAME,"body").text


try:
    resize(1366,768)
    driver.get("http://127.0.0.1:5173")
    wait.until(lambda d:"CONNECTED" in text())
    for scenario in (("strong","weak","transport","ipv6","natt","partial","replay") if ARGS.live else ("strong","weak","replay","partial","ipv6")):
        click_nav("New Analysis")
        is_live=ARGS.live and scenario not in ("partial","replay")
        folder=ROOT/f"runtime/live/{scenario}" if is_live else ROOT/f"demo/{scenario}"
        path=folder/("negotiation.pcap" if is_live else scenario+".pcap")
        driver.find_element(By.CSS_SELECTOR,'input[aria-label="Capture file"]').send_keys(str(path))
        telemetry=folder/"telemetry.json"
        if telemetry.exists():
            driver.find_element(By.CSS_SELECTOR,'input[aria-label="Telemetry file"]').send_keys(str(telemetry))
        label=driver.find_element(By.CSS_SELECTOR,'input[placeholder^="e.g."]')
        label.send_keys(("REAL LAB · browser " if is_live else "SYNTHETIC FIXTURE · browser ")+scenario)
        button=wait.until(EC.element_to_be_clickable((By.XPATH,"//button[normalize-space()='Run analysis']")))
        button.click()
        wait.until(EC.text_to_be_present_in_element((By.TAG_NAME,"h1"),"Overview"))
        wait.until(lambda d:"Capture at a glance" in text())
        body=text()
        uploaded[scenario]=driver.find_element(By.CSS_SELECTOR,'select[aria-label="Selected analysis"]').get_attribute("value")
        if not is_live:
            assert "SYNTHETIC FIXTURE" in body
        if scenario=="strong":
            assert "97.5" in body and "ACCEPT" in body
            driver.save_screenshot(str(OUT/"strong-overview-1366.png"))
        elif scenario=="weak":
            expected=str(json.loads((ROOT/"docs/LIVE_PROTOCOL_VALIDATION.json").read_text())["weak"]["score"]["security_score"]) if ARGS.live else "30.5"
            assert expected in body and "HARDEN" in body
        elif scenario=="partial":
            assert "UNAVAILABLE" in body and "UNKNOWN" in body
        results.append({"scenario":scenario,"upload":"PASS"})
    # Re-select strong for all pages and ensure responsive content is present.
    selector=driver.find_element(By.CSS_SELECTOR,'select[aria-label="Selected analysis"]')
    Select(selector).select_by_value(uploaded["strong"])
    wait.until(lambda d:"97.5" in text())
    for width,height in ((1366,768),(1920,1080)):
        resize(width,height)
        for name in ("Overview","New Analysis","Compare Analyses","Evidence Provenance","Protocol Analysis","Security Associations","Encrypted Traffic AI","Security Assessment",
                     "Findings","Threat Matrix","Reports","Testbed / Demo","System"):
            click_nav(name)
            if name=="Compare Analyses":
                Select(driver.find_element(By.CSS_SELECTOR,'select[aria-label="Left analysis"]')).select_by_value(uploaded["strong"])
                Select(driver.find_element(By.CSS_SELECTOR,'select[aria-label="Right analysis"]')).select_by_value(uploaded["weak"])
                wait.until(lambda d:"Configuration changes" in text())
                assert "RESOLVED" in text() and "ADDED" in text()
                driver.save_screenshot(str(OUT/f"compare-{width}.png"))
            if name in ("Encrypted Traffic AI","System"):
                wait.until(lambda d:"RandomForest" in text())
                assert "EXPERIMENTAL" in text() and "0.32" in text()
            if name=="Evidence Provenance":
                assert all(source in text() for source in ("OBSERVED","ASSISTED","INFERRED","UNKNOWN","DERIVED"))
            assert driver.execute_script("return document.documentElement.scrollWidth<=window.innerWidth")
            assert driver.execute_script("const n=document.querySelector('nav'); return n.clientHeight>0 && n.getBoundingClientRect().bottom<=window.innerHeight")
            results.append({"page":name,"viewport":f"{width}x{height}","render":"PASS"})
    click_nav("Reports")
    for kind in ("executive","technical"):
        before=set(OUT.glob("*-"+kind+".html"))
        driver.find_element(By.PARTIAL_LINK_TEXT,"Download "+kind).click()
        wait.until(lambda d:bool(set(OUT.glob("*-"+kind+".html"))-before))
    for kind in ("executive","technical"):
        before=set(OUT.glob("*-"+kind+".pdf"))
        driver.find_element(By.PARTIAL_LINK_TEXT,"Download "+kind+" PDF").click()
        wait.until(lambda d:bool(set(OUT.glob("*-"+kind+".pdf"))-before))
        newest=next(iter(set(OUT.glob("*-"+kind+".pdf"))-before))
        assert newest.read_bytes().startswith(b"%PDF-")
    before=set(OUT.glob("ipseclens-*.json"))
    driver.find_element(By.LINK_TEXT,"Download Analysis JSON").click()
    wait.until(lambda d:bool(set(OUT.glob("ipseclens-*.json"))-before))
    exported=json.loads(next(iter(set(OUT.glob("ipseclens-*.json"))-before)).read_text())
    assert exported["analysis_id"]==uploaded["strong"] and exported["score"]["security_score"]==97.5
    results.append({"downloads":"HTML/PDF executive + technical and typed JSON PASS"})
    # Delete only a run created by this walkthrough, never an existing user analysis.
    Select(driver.find_element(By.CSS_SELECTOR,'select[aria-label="Selected analysis"]')).select_by_value(uploaded["partial"])
    wait.until(lambda d:driver.find_element(By.LINK_TEXT,"Download Analysis JSON").get_attribute("href").endswith(uploaded["partial"]+"/export"))
    driver.find_element(By.XPATH,"//button[text()='Delete analysis']").click()
    assert uploaded["partial"] in text()
    driver.find_element(By.CSS_SELECTOR,'input[aria-label="Type analysis ID to confirm"]').send_keys(uploaded["partial"])
    driver.find_element(By.XPATH,"//button[text()='Confirm delete analysis']").click()
    wait.until(lambda d:"Your evidence workspace is ready" in text())
    assert driver.find_element(By.CSS_SELECTOR,'select[aria-label="Selected analysis"]').get_attribute("value")==""
    results.append({"confirmed_delete_and_selection_clear":"PASS"})
    Select(driver.find_element(By.CSS_SELECTOR,'select[aria-label="Selected analysis"]')).select_by_value(uploaded["strong"])
    click_nav("Overview")
    wait.until(lambda d:"97.5" in text())
    resize(1920,1080)
    driver.save_screenshot(str(OUT/"strong-overview-1920.png"))
    resize(390,844)
    assert driver.execute_script("return document.documentElement.scrollWidth<=window.innerWidth")
    driver.save_screenshot(str(OUT/"overview-mobile.png"))
    errors=[x for x in driver.get_log("browser") if x["level"]=="SEVERE" and "favicon" not in x["message"]]
    assert not errors,errors
    (OUT/"walkthrough.json").write_text(json.dumps({"results":results,"console_errors":errors,
        "reports":[p.name for p in OUT.glob("*.html")],"viewports":["1366x768","1920x1080","390x844"]},indent=2)+"\n")
    print(json.dumps(results,indent=2))
finally:
    driver.quit()
