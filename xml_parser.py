import xml.etree.ElementTree as ET

root = ET.parse("test.xml")

category = root.find("category")
for i in category.findall("script"):
    print(i.get("name"))
