from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    items = dictionary.get(key, [])
    return items