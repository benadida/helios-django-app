"""
Forms for Helios
"""

from django import forms
from models import Election

class ElectionForm(forms.Form):
  short_name = forms.CharField(max_length=25, help_text='no spaces, will be part of the URL for your election, e.g. my-club-2010')
  name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'size':60}), help_text='the pretty name for your election, e.g. My Club 2010 Election')
  description = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={'cols': 70, 'wrap': 'soft'}))
  use_voter_aliases = forms.BooleanField(required=False, initial=False, help_text='if selected, voter identities will be replaced with aliases, e.g. "V12", in the ballot tracking center')
  
  # times
  voting_starts_at = forms.DateTimeField(help_text= 'the time, in UTC, when voting begins', required=False, initial=None)
  voting_ends_at = forms.DateTimeField(help_text= 'the time, in UTC, when voting ends', required=False, initial=None)  
  
class EmailVotersForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=2000, widget=forms.Textarea)

