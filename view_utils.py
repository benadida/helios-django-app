"""
Utilities for all views

Ben Adida (12-30-2008)
"""

from django.template import Context, Template, loader
from django.http import HttpResponse, Http404
from django.shortcuts import render_to_response

import utils

from auth.security import get_user

import helios

from django.conf import settings

##
## BASICS
##

SUCCESS = HttpResponse("SUCCESS")

# FIXME: error code
FAILURE = HttpResponse("FAILURE")

##
## template abstraction
##
def prepare_vars(request, vars):
  vars_with_user = vars.copy()
  vars_with_user['user'] = get_user(request)
  
  # csrf protection
  if request.session.has_key('csrf_token'):
    vars_with_user['csrf_token'] = request.session['csrf_token']
    
  vars_with_user['utils'] = utils
  vars_with_user['settings'] = settings
  vars_with_user['HELIOS_STATIC'] = '/static/helios/helios'
  vars_with_user['TEMPLATE_BASE'] = helios.TEMPLATE_BASE
  vars_with_user['CURRENT_URL'] = request.path
  
  return vars_with_user

def render_template(request, template_name, vars = {}):
  t = loader.get_template(template_name + '.html')
  
  vars_with_user = prepare_vars(request, vars)
  
  return render_to_response('helios/templates/%s.html' % template_name, vars_with_user)
  
def render_json(json_txt):
  return HttpResponse(json_txt)

# decorator
def json(func):
    """
    A decorator that serializes the output to JSON before returning to the
    web client.
    """
    def convert_to_json(self, *args, **kwargs):
      return render_json(utils.to_json(func(self, *args, **kwargs)))

    return convert_to_json
    
