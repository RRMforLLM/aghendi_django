from django import forms
from .models import Agenda

class AgendaKeyForm(forms.ModelForm):
    class Meta:
        model = Agenda
        fields = ['key', 'key_visible']
        widgets = {
            'key': forms.TextInput(attrs={'class': 'form-control'}),
            'key_visible': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }
        labels = {
            'key_visible': 'Visibility'
        }