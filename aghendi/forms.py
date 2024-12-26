from django import forms
from .models import Agenda

class AgendaKeyForm(forms.ModelForm):
    class Meta:
        model = Agenda
        fields = ['key']