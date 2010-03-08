"""
Forms for Helios
"""

from django import forms
from models import Election

class ElectionForm(forms.Form):
  short_name = forms.CharField(max_length=25)
  name = forms.CharField(max_length=100)
  description = forms.CharField(max_length=2000, widget=forms.Textarea)
  use_voter_aliases = forms.BooleanField(required=False, initial=False)
  
  # times
  voting_starts_at = forms.DateTimeField(required=False, initial=None)
  voting_ends_at = forms.DateTimeField(required=False, initial=None)  
  
class EmailVotersForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=2000, widget=forms.Textarea)
