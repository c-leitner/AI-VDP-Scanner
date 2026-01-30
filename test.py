import logging
from usp.tree import sitemap_tree_for_homepage

# Enable detailed debug logging
logging.basicConfig(level=logging.DEBUG)

def main():
    print("Starting sitemap parsing for https://www.bmw.at ...")
    try:
        tree = sitemap_tree_for_homepage("https://www.bmw.at")
        if tree is None:
            print("No sitemap tree returned.")
        else:
            for page in tree.all_pages():
                print(page.url)
    except Exception as e:
        print(f"Exception occurred: {e}")

if __name__ == "__main__":
    main()