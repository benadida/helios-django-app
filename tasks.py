"""
Celery queued tasks for Helios

2010-08-01
ben@adida.net
"""

from celery.decorators import task

from models import *
from view_utils import render_template_raw
import signals

import copy


@task()
def cast_vote_verify_and_store(cast_vote_id):
    cast_vote = CastVote.objects.get(id = cast_vote_id)
    result = cast_vote.verify_and_store()

    voter = cast_vote.voter
    election = voter.election
    user = voter.user
    if result:
        # send the signal
        signals.vote_cast.send(sender=election, election=election, user=user, voter=voter, cast_vote=cast_vote)
    else:
        # FIXME: do something about a bad vote
        pass
    
@task()
def voters_email(election_id, subject_template, body_template, extra_vars={}):
    election = Election.objects.get(id = election_id)
    for voter in election.voter_set.all():
        single_voter_email.delay(voter.uuid, subject_template, body_template, extra_vars)

@task()
def single_voter_email(voter_uuid, subject_template, body_template, extra_vars={}):
    voter = Voter.objects.get(uuid = voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter' : voter})

    subject = render_template_raw(None, subject_template, the_vars)
    body = render_template_raw(None, body_template, the_vars)

    print "subject: %s" % subject
    print "body:\n%s" % body

    voter.user.send_message(subject, body)

@task()
def election_compute_tally(election_id):
    election = Election.objects.get(id = election_id)
    election.compute_tally()
    
    if election.has_helios_trustee():
        tally_helios_decrypt.delay(election_id = election.id)

@task()
def tally_helios_decrypt(election_id):
    election = Election.objects.get(id = election_id)
    election.helios_trustee_decrypt()

@task()
def voter_file_process(voter_file_id):
    voter_file = VoterFile.objects.get(id = voter_file_id)
    voter_file.process()
