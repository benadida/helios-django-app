"""
Helios Security -- mostly access control

Ben Adida (ben@adida.net)
"""

# nicely update the wrapper function
from functools import update_wrapper

from django.core.exceptions import *
from django.conf import settings

from models import *
from auth.security import get_user

from django.http import HttpResponseRedirect

import helios

#
# some common election checks
#
def do_election_checks(election, props):
  # frozen
  if props.has_key('frozen'):
    frozen = props['frozen']
  else:
    frozen = None
  
  # newvoters (open for registration)
  if props.has_key('newvoters'):
    newvoters = props['newvoters']
  else:
    newvoters = None
  
  # frozen check
  if frozen != None:
    if frozen and not election.frozen_at:
      raise PermissionDenied()
    if not frozen and election.frozen_at:
      raise PermissionDenied()
    
  # open for new voters check
  if newvoters != None:
    if election.can_add_voters() != newvoters:
      raise PermissionDenied()

  
def get_election_by_uuid(uuid):
  if not uuid:
    raise Exception("no election ID")
      
  return Election.get_by_uuid(uuid)
  
# decorator for views that pertain to an election
# takes parameters:
# frozen - is the election frozen
# newvoters - does the election accept new voters
def election_view(**checks):
  
  def election_view_decorator(func):
    def election_view_wrapper(request, election_id=None, *args, **kw):
      election = get_election_by_uuid(election_id)
    
      # do checks
      do_election_checks(election, checks)
    
      return func(request, election, *args, **kw)

    return update_wrapper(election_view_wrapper, func)
    
  return election_view_decorator

def user_can_admin_election(user, election):
  return election.admin == user
  
def api_client_can_admin_election(api_client, election):
  return election.api_client == api_client and api_client != None
  
# decorator for checking election admin access, and some properties of the election
# frozen - is the election frozen
# newvoters - does the election accept new voters
def election_admin(**checks):
  
  def election_admin_decorator(func):
    def election_admin_wrapper(request, election_id=None, *args, **kw):
      election = get_election_by_uuid(election_id)

      user = get_user(request)
      if not user or not (user == election.admin):
        raise PermissionDenied()
        
      # do checks
      do_election_checks(election, checks)
        
      return func(request, election, *args, **kw)

    return update_wrapper(election_admin_wrapper, func)
    
  return election_admin_decorator

def can_create_election(request):
  user = get_user(request)
  if helios.ADMIN_ONLY:
    return user == helios.ADMIN
  else:
    return user != None
  