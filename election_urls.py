"""
Helios URLs for Election related stuff

Ben Adida (ben@adida.net)
"""

from django.conf.urls.defaults import *

from helios.views import *

urlpatterns = patterns('',
    (r'^$', one_election),

    # adding trustees
    (r'^/trustees/$', list_trustees),
    (r'^/trustees/view$', list_trustees_view),
    (r'^/trustees/keygenerator$', election_keygenerator),
    (r'^/trustees/new$', new_trustee),
    (r'^/trustees/delete$', delete_trustee),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/decrypt-and-prove$', trustee_decrypt_and_prove),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/upload-decryption$', trustee_upload_decryption),
    
    # election voting-process actions
    (r'^/view$', one_election_view),
    (r'^/result$', one_election_result),
    (r'^/result_proof$', one_election_result_proof),
    (r'^/bboard$', one_election_bboard),

    # construct election
    (r'^/set_pk$', one_election_set_pk),
    (r'^/build$', one_election_build),
    (r'^/save_questions$', one_election_save_questions),
    (r'^/register$', one_election_register),
    (r'^/freeze$', one_election_freeze), # includes freeze_2 as POST target
    
    # computing tally
    (r'^/compute_tally$', one_election_compute_tally),
    (r'^/combine_decryptions$', combine_decryptions),
    
    # casting a ballot before we know who the voter is
    (r'^/cast$', one_election_cast),
    (r'^/cast_confirm$', one_election_cast_confirm),
    
    # managing voters
    (r'^/voters/$', voter_list),
    (r'^/voters/(?P<voter_id>[^/]+)$', one_voter),
    (r'^/voters/(?P<voter_id>[^/]+)/delete$', one_voter_delete),
    
    # ballots
    (r'^/ballots/$', ballot_list),

)
