"""Optional Selenium/Chromium release check; operates only on local loopback UI."""
import json
import shutil
from selenium.webdriver.chrome.service import Service
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"runtime/browser"
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
    for scenario in ("strong","weak","replay","partial","ipv6"):
        click_nav("New Analysis")
        driver.find_element(By.CSS_SELECTOR,'input[aria-label="Capture file"]').send_keys(str(ROOT/f"demo/{scenario}/{scenario}.pcap"))
        telemetry=ROOT/f"demo/{scenario}/telemetry.json"
        if telemetry.exists():
            driver.find_element(By.CSS_SELECTOR,'input[aria-label="Telemetry file"]').send_keys(str(telemetry))
        label=driver.find_element(By.CSS_SELECTOR,'input[placeholder^="e.g."]')
        label.send_keys("SYNTHETIC FIXTURE · browser "+scenario)
        button=wait.until(EC.element_to_be_clickable((By.XPATH,"//button[normalize-space()='Run analysis']")))
        button.click()
        wait.until(EC.text_to_be_present_in_element((By.TAG_NAME,"h1"),"Overview"))
        wait.until(lambda d:"Capture at a glance" in text())
        body=text()
        if scenario=="strong":
            assert "97.5" in body and "ACCEPT" in body
            driver.save_screenshot(str(OUT/"strong-overview-1366.png"))
        elif scenario=="weak":
            assert "30.5" in body and "HARDEN" in body
        elif scenario=="partial":
            assert "UNAVAILABLE" in body and "UNKNOWN" in body
        results.append({"scenario":scenario,"upload":"PASS"})
    # Re-select strong for all pages and ensure responsive content is present.
    selector=driver.find_element(By.CSS_SELECTOR,'select[aria-label="Selected analysis"]')
    from selenium.webdriver.support.ui import Select
    Select(selector).select_by_visible_text("SYNTHETIC FIXTURE · browser strong")
    wait.until(lambda d:"97.5" in text())
    for name in ("Protocol Analysis","Security Associations","Encrypted Traffic AI","Security Assessment",
                 "Findings","Threat Matrix","Reports","Testbed / Demo","System"):
        click_nav(name)
        assert driver.execute_script("return document.documentElement.scrollWidth<=window.innerWidth")
        results.append({"page":name,"render":"PASS"})
    click_nav("Reports")
    for kind in ("executive","technical"):
        driver.find_element(By.PARTIAL_LINK_TEXT,"Download "+kind).click()
        wait.until(lambda d:any(OUT.glob("*-"+kind+".html")))
    click_nav("Overview")
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
