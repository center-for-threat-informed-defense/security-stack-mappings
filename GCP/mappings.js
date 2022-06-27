window.onload = function () {
    // Rewrite navigator links to point to ATT&CK navigator.
    let nav_links = document.evaluate("//a[contains(.,'Navigator Layer')]", document, null, XPathResult.ANY_TYPE, null);
    let nav_link = null;
    let links = [];
    while (nav_link = nav_links.iterateNext()) {
        links.push(nav_link);
    }
    for (let nav_link of links) {
        nav_link.href = "https://mitre-attack.github.io/attack-navigator/#layerURL=" + nav_link.href;
        nav_link.target = "_blank";
    }

    // Rewrite YAML links to point to treedoc.org.
    let mapping_links = document.evaluate("//a[contains(.,'Mapping File')]", document, null, XPathResult.ANY_TYPE, null);
    let mapping_link = null;
    let mlinks = [];
    while (mapping_link = mapping_links.iterateNext()) {
        mlinks.push(mapping_link);
    }
    for (let mapping_link of mlinks) {
        mapping_link.href = "https://www.treedoc.org/?dataUrl=" + mapping_link.href;
        mapping_link.target = "_blank";
    }
};
