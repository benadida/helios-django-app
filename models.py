# -*- coding: utf-8 -*-
"""
Data Objects for Helios.

Ben Adida
(ben@adida.net)
"""

from django.db import models
from django.utils import simplejson
from django.conf import settings

import datetime, logging, uuid

from crypto import electionalgs, algs, utils
from helios import utils as heliosutils
import helios

# useful stuff in auth
from auth.models import User, AUTH_SYSTEMS
from auth.jsonfield import JSONField
  
# global counters
GLOBAL_COUNTER_VOTERS = 'global_counter_voters'
GLOBAL_COUNTER_CAST_VOTES = 'global_counter_cast_votes'
GLOBAL_COUNTER_ELECTIONS = 'global_counter_elections'

class Election(models.Model, electionalgs.Election):
  admin = models.ForeignKey(User)
  
  uuid = models.CharField(max_length=50, null=False)
  
  short_name = models.CharField(max_length=100)
  name = models.CharField(max_length=250)
  
  description = models.TextField()
  public_key = JSONField(algs.EGPublicKey, null=True)
  private_key = JSONField(algs.EGSecretKey, null=True)
  questions = JSONField(null=True)
  
  # eligibility is a JSON field, which lists auth_systems and eligibility details for that auth_system, e.g.
  # [{'auth_system': 'cas', 'constraint': [{'year': 'u12'}, {'year':'u13'}]}, {'auth_system' : 'password'}, {'auth_system' : 'openid', 'constraint': [{'host':'http://myopenid.com'}]}]
  eligibility = JSONField(null=True)

  # open registration?
  # this is now used to indicate the state of registration,
  # whether or not the election is frozen
  openreg = models.BooleanField(default=False)
  
  # featured election?
  featured_p = models.BooleanField(default=False)
    
  # voter aliases?
  use_voter_aliases = models.BooleanField(default=False)
  
  # where votes should be cast
  cast_url = models.CharField(max_length = 500)
  
  # dates at which things happen for the election
  frozen_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  archived_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  
  # dates for the election steps, as scheduled
  # these are always UTC
  registration_starts_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_starts_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_ends_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  tallying_starts_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  
  # dates when things were forced to be performed
  voting_started_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_extended_until = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_ended_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  tallying_started_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  tallying_finished_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  tallies_combined_at = models.DateTimeField(auto_now_add=False, default=None, null=True)

  # the hash of all voters (stored for large numbers)
  voters_hash = models.CharField(max_length=100, null=True)
  
  # encrypted tally, each a JSON string
  # used only for homomorphic tallies
  encrypted_tally = JSONField(electionalgs.Tally, null=True)

  # results of the election
  result = JSONField(null=True)

  # decryption proof, a JSON object
  result_proof = JSONField(null=True)
  
  @property
  def num_cast_votes(self):
    return self.voter_set.exclude(vote=None).count()

  @property
  def num_voters(self):
    return self.voter_set.count()

  @property
  def encrypted_tally_hash(self):
    if not self.encrypted_tally:
      return None

    return utils.hash_b64(self.encrypted_tally.toJSON())

  @classmethod
  def get_featured(cls):
    return cls.objects.filter(featured_p = True).order_by('short_name')
    
  @classmethod
  def get_or_create(cls, **kwargs):
    return cls.objects.get_or_create(short_name = kwargs['short_name'], defaults=kwargs)

  @classmethod
  def get_by_user_as_admin(cls, user, include_archived=False):
    query = cls.objects.filter(admin = user)
    if include_archived:
      query = query.filter('archived_at', None)
    return query
    
  @classmethod
  def get_by_user_as_voter(cls, user):
    return [v.election for v in Voter.get_by_user(user)]
    
  @classmethod
  def get_by_uuid(cls, uuid):
    try:
      return cls.objects.get(uuid=uuid)
    except cls.DoesNotExist:
      return None
  
  @classmethod
  def get_by_short_name(cls, short_name):
    try:
      return cls.objects.get(short_name=short_name)
    except cls.DoesNotExist:
      return None

  def add_voters_file(self, uploaded_file):
    """
    expects a django uploaded_file data structure, which has filename, content, size...
    """
    random_filename = str(uuid.uuid1())
    new_voter_file = VoterFile(election = self)
    new_voter_file.voter_file.save(random_filename, uploaded_file)
    self.append_log(ElectionLog.VOTER_FILE_ADDED)
  
  def user_eligible_p(self, user):
    """
    Checks if a user is eligible for this election.
    """
    # registration closed, then eligibility doesn't come into play
    if not self.openreg:
      return False
    
    if self.eligibility == None:
      return True
      
    # is the user eligible for one of these cases?
    for eligibility_case in self.eligibility:
      if user.is_eligible_for(eligibility_case):
        return True
        
    return False
  
  def voting_has_started(self):
    """
    has voting begun? voting begins if the election is frozen, at the prescribed date or at the date that voting was forced to start
    """
    return self.frozen_at != None and (self.voting_starts_at == None or (datetime.datetime.utcnow() >= (self.voting_started_at or self.voting_starts_at)))
    
  def voting_has_stopped(self):
    """
    has voting stopped? if tally computed, yes, otherwise if we have passed the date voting was manually stopped at,
    or failing that the date voting was extended until, or failing that the date voting is scheduled to end at.
    """
    voting_end = self.voting_ended_at or self.voting_extended_until or self.voting_ends_at
    return (voting_end != None and datetime.datetime.utcnow() >= voting_end) or self.encrypted_tally

  @property
  def issues_before_freeze(self):
    issues = []
    if self.questions == None or len(self.questions) == 0:
      issues.append("no questions")
  
    trustees = Trustee.get_by_election(self)
    if len(trustees) == 0:
      issues.append("no trustees")

    return issues
    

  def ready_for_tallying(self):
    return datetime.datetime.utcnow() >= self.tallying_starts_at
  
  def ready_for_decryption(self):
    return self.encrypted_tally != None
    
  def ready_for_decryption_combination(self):
    """
    do we have a tally from all trustees?
    """
    for t in Trustee.get_by_election(self):
      if not t.decryption_factors:
        return False
    
    return True
    
  def combine_decryptions(self):
    """
    combine all of the decryption results
    """
    
    # gather the decryption factors
    trustees = Trustee.get_by_election(self)
    decryption_factors = [t.decryption_factors for t in trustees]
    
    self.result = self.encrypted_tally.decrypt_from_factors(decryption_factors, self.public_key)

    self.append_log(ElectionLog.DECRYPTIONS_COMBINED)

    self.save()
  
  def generate_voters_hash(self):
    """
    look up the list of voters, make a big file, and hash it
    FIXME: for more than 1000 voters, need to loop multiple times
    FIXME: is this even used anymore?
    """
    if self.openreg:
      self.voters_hash = None
    else:
      voters = Voter.get_by_election(self)
      voters_json = utils.to_json([v.toJSONDict() for v in voters])
      self.voters_hash = utils.hash_b64(voters_json)
    
  def increment_voters(self):
    ## FIXME
    return 0
    
  def increment_cast_votes(self):
    ## FIXME
    return 0
        
  def freeze(self):
    """
    election is frozen when the voter registration, questions, and trustees are finalized
    """
    self.frozen_at = datetime.datetime.utcnow()
    
    # voters hash
    self.generate_voters_hash()
    
    # public key for trustees
    trustees = Trustee.get_by_election(self)
    combined_pk = trustees[0].public_key
    for t in trustees[1:]:
      combined_pk = combined_pk * t.public_key
      
    self.public_key = combined_pk
    
    # log it
    self.append_log(ElectionLog.FROZEN)

    self.save()

  def generate_trustee(self, params):
    """
    generate a trustee including the secret key,
    thus a helios-based trustee
    """
    # FIXME: generate the keypair
    keypair = params.generate_keypair()

    # create the trustee
    trustee = Trustee(election = self)
    trustee.uuid = str(uuid.uuid1())
    trustee.name = 'Helios'
    trustee.email = settings.DEFAULT_FROM_EMAIL
    trustee.public_key = keypair.pk
    trustee.secret_key = keypair.sk
    
    # FIXME: compute it
    trustee.public_key_hash = utils.hash_b64(utils.to_json(trustee.public_key.toJSONDict()))
    trustee.pok = trustee.secret_key.prove_sk(algs.DLog_challenge_generator)

    trustee.save()

  def has_helios_trustee(self):
    num_helios_trustees = len(self.trustee_set.exclude(secret_key = None))
    return num_helios_trustees > 0

  def append_log(self, text):
    item = ElectionLog(election = self, log=text, at=datetime.datetime.utcnow())
    item.save()
    return item

  def get_log(self):
    return self.electionlog_set.order_by('-at')

  @property
  def url(self):
    return helios.get_election_url(self)

class ElectionLog(models.Model):
  """
  a log of events for an election
  """

  FROZEN = "frozen"
  VOTER_FILE_ADDED = "voter file added"
  DECRYPTIONS_COMBINED = "decryptions combined"

  election = models.ForeignKey(Election)
  log = models.CharField(max_length=500)
  at = models.DateTimeField(auto_now_add=True)

class VoterFile(models.Model):
  """
  A model to store files that are lists of voters to be processed
  """
  # path where we store voter upload 
  PATH = settings.VOTER_UPLOAD_REL_PATH

  election = models.ForeignKey(Election)
  voter_file = models.FileField(upload_to=PATH, max_length=250)
  uploaded_at = models.DateTimeField(auto_now_add=True)
  processing_started_at = models.DateTimeField(auto_now_add=False, null=True)
  processing_finished_at = models.DateTimeField(auto_now_add=False, null=True)
  num_voters = models.IntegerField(null=True)
    
class Voter(models.Model, electionalgs.Voter):
  election = models.ForeignKey(Election)
  
  name = models.CharField(max_length = 200, null=True)
  voter_type = models.CharField(max_length = 100)
  voter_id = models.CharField(max_length = 100)
  uuid = models.CharField(max_length = 50)
  
  # if election uses aliases
  alias = models.CharField(max_length = 100, null=True)
  
  # we keep a copy here for easy tallying
  vote = JSONField(electionalgs.EncryptedVote, null=True)
  vote_hash = models.CharField(max_length = 100, null=True)
  cast_at = models.DateTimeField(auto_now_add=False, null=True)
  
  @classmethod
  def get_by_election(cls, election, cast=None, order_by='voter_id', after=None, limit=None):
    query = cls.objects.filter(election = election)
    
    # the boolean check is not stupid, this is ternary logic
    # none means don't care if it's cast or not
    if cast == True:
      query = query.exclude(cast_at = None)
    elif cast == False:
      query = query.filter(cast_at = None)

    # little trick to get around GAE limitation
    # order by uuid only when no inequality has been added
    if cast == None or order_by == 'cast_at' or order_by =='-cast_at':
      query = query.order_by(order_by)
      
      # if we want the list after a certain UUID, add the inequality here
      if after:
        if order_by[0] == '-':
          field_name = "%s__gt" % order_by[1:]
        else:
          field_name = "%s__gt" % order_by
        conditions = {field_name : after}
        query = query.filter (**conditions)
    
    if limit:
      query = query[:limit]
      
    return query
  
  @classmethod
  def get_all_by_election_in_chunks(cls, election, cast=None, chunk=100):
    return cls.get_by_election(election)

  @classmethod
  def get_by_election_and_voter_id(cls, election, voter_id):
    query = cls.objects.filter(election = election, voter_id = voter_id)

    try:
      return query[0]
    except:
      return None
    
  @classmethod
  def get_by_election_and_user(cls, election, user):
    query = cls.objects.filter(election = election, voter_id = user.user_id, voter_type= user.user_type)

    try:
      return query[0]
    except:
      return None
      
  @classmethod
  def get_by_election_and_uuid(cls, election, uuid):
    query = cls.objects.filter(election = election, uuid = uuid)

    try:
      return query[0]
    except:
      return None

  @classmethod
  def get_by_user(cls, user):
    return cls.objects.filter(voter_type = user.user_type, voter_id = user.user_id)

  @property
  def user(self):
    return User.get_by_type_and_id(self.voter_type, self.voter_id)
    
  @property
  def election_uuid(self):
    return self.election.uuid
  
  def store_vote(self, cast_vote):
    # only store the vote if it's cast later than the current one
    if self.cast_at and cast_vote.cast_at < self.cast_at:
      return

    self.vote = cast_vote.vote
    self.vote_hash = cast_vote.vote_hash
    self.cast_at = cast_vote.cast_at
    self.save()
  
  def last_cast_vote(self):
    return CastVote(vote = self.vote, vote_hash = self.vote_hash, cast_at = self.cast_at, voter=self)
    
  
class CastVote(models.Model, electionalgs.CastVote):
  # the reference to the voter provides the voter_uuid
  voter = models.ForeignKey(Voter)
  
  # a json array, which should contain election_uuid and election_hash
  vote = JSONField(electionalgs.EncryptedVote)

  # cache the hash of the vote
  vote_hash = models.CharField(max_length=100)

  cast_at = models.DateTimeField(auto_now_add=True)

  # when is the vote verified?
  verified_at = models.DateTimeField(null=True)
  invalidated_at = models.DateTimeField(null=True)
  
  @property
  def voter_uuid(self):
    return self.voter.uuid  
    
  @property
  def voter_hash(self):
    return self.voter.hash
  
  @classmethod
  def get_by_voter(cls, voter):
    return cls.objects.filter(voter = voter).order_by('-cast_at')

  def verify_and_store(self):
    if self.vote.verify(self.voter.election):
      self.verified_at = datetime.datetime.utcnow()
    else:
      self.invalidated_at = datetime.datetime.utcnow()
      
    # save and store the vote as the voter's last cast vote
    self.save()
    self.voter.store_vote(self)
    
    
class AuditedBallot(models.Model):
  """
  ballots for auditing
  """
  election = models.ForeignKey(Election)
  raw_vote = models.TextField()
  vote_hash = models.CharField(max_length=100)
  added_at = models.DateTimeField(auto_now_add=True)

  @classmethod
  def get(cls, election, vote_hash):
    return cls.objects.get(election = election, vote_hash = vote_hash)

  @classmethod
  def get_by_election(cls, election, after=None, limit=None):
    query = cls.objects.filter(election = election).order_by('vote_hash')

    # if we want the list after a certain UUID, add the inequality here
    if after:
      query = query.filter(vote_hash__gt = after)

    if limit:
      query = query[:limit]

    return query
    
class Trustee(models.Model, electionalgs.Trustee):
  election = models.ForeignKey(Election)
  
  uuid = models.CharField(max_length=50)
  name = models.CharField(max_length=200)
  email = models.EmailField()
  secret = models.CharField(max_length=100)
  
  # public key
  public_key = JSONField(algs.EGPublicKey, null=True)
  public_key_hash = models.CharField(max_length=100)

  # secret key
  # if the secret key is present, this means
  # Helios is playing the role of the trustee.
  secret_key = JSONField(algs.EGSecretKey, null=True)
  
  # proof of knowledge of secret key
  pok = JSONField(algs.DLogProof, null=True)
  
  # decryption factors
  decryption_factors = JSONField(null=True)
  decryption_proofs = JSONField(null=True)
  
  def save(self, *args, **kwargs):
    """
    override this just to get a hook
    """
    # not saved yet?
    if not self.secret:
      self.secret = heliosutils.random_string(12)
      self.election.append_log("Trustee %s added" % self.name)
      
    super(Trustee, self).save(*args, **kwargs)
  
  @classmethod
  def get_by_election(cls, election):
    return cls.objects.filter(election = election)

  @classmethod
  def get_by_uuid(cls, uuid):
    return cls.objects.get(uuid = uuid)
    
  @classmethod
  def get_by_election_and_uuid(cls, election, uuid):
    return cls.objects.get(election = election, uuid = uuid)

  @classmethod
  def get_by_election_and_email(cls, election, email):
    return cls.objects.get(election = election, email = email)
    
  def verify_decryption_proofs(self):
    """
    verify that the decryption proofs match the tally for the election
    """
    # verify_decryption_proofs(self, decryption_factors, decryption_proofs, public_key, challenge_generator):
    return self.election.encrypted_tally.verify_decryption_proofs(self.decryption_factors, self.decryption_proofs, self.public_key, algs.EG_fiatshamir_challenge_generator)
    
