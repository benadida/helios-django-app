
TEMPLATE_BASE = "helios/templates/base.html"

# a setting to ensure that only admins can create an election
ADMIN_ONLY = False
ADMIN = None

# allow upload of voters via CSV?
VOTERS_UPLOAD = True

# allow emailing of voters?
VOTERS_EMAIL = True

# a function that 
CHECK_ELIGIBILITY_FUNC = None

from django.conf import settings
from django.core.urlresolvers import reverse

# get the short path for the URL
def get_election_url(election):
  from views import one_election_view
  return settings.URL_HOST + reverse(one_election_view, args=[election.uuid])