# -*- coding: utf-8 -*-
from django.conf.urls.defaults import *

from django.conf import settings

from views import *

urlpatterns = None

urlpatterns = patterns('',
  (r'^$', home),
  (r'^about$', about),

  # election shortcut by shortname
  (r'^e/(?P<election_short_name>[^/]+)$', election_shortcut),
  
  # election
  (r'^elections/params$', election_params),
  (r'^elections/verifier$', election_verifier),
  (r'^elections/single_ballot_verifier$', election_single_ballot_verifier),
  (r'^elections/new$', election_new),
  
  (r'^elections/(?P<election_id>[^/]+)', include('helios.election_urls')),
  
)


