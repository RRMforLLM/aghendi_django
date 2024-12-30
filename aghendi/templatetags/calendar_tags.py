from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    items = dictionary.get(key, [])
    print(f"Template filter called with key {key}, found {len(items)} items")
    return items