"""
Forms for Helios
"""

from django import forms

class ElectionForm(forms.Form):
  short_name = forms.CharField(max_length=25)
  name = forms.CharField(max_length=100)
  description = forms.CharField(max_length=2000, widget=forms.Textarea)
  use_voter_aliases = forms.BooleanField(required=False, initial=False)
  
  # these should have defaults
  ballot_type = forms.CharField(max_length=60, widget=forms.HiddenInput, initial='homomorphic')
  tally_type = forms.CharField(max_length=60, widget=forms.HiddenInput, initial='homomorphic')
  
class EmailVotersForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=2000, widget=forms.Textarea)