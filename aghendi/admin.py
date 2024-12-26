from django.contrib import admin
from .models import Agenda, AgendaSection, AgendaElement, ElementComment

@admin.register(Agenda)
class AgendaAdmin(admin.ModelAdmin):
    list_display = ('name', 'creator', 'id')
    filter_horizontal = ('editors', 'members')

@admin.register(AgendaSection)
class AgendaSectionAdmin(admin.ModelAdmin):
    list_display = ('name', 'agenda', 'id')

@admin.register(AgendaElement)
class AgendaElementAdmin(admin.ModelAdmin):
    list_display = ('subject', 'section', 'emission', 'deadline')

@admin.register(ElementComment)
class ElementCommentAdmin(admin.ModelAdmin):
    list_display = ('user', 'element', 'created_at')