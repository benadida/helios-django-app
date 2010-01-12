# -*- coding: utf-8 -*-
"""
Data Objects for Helios.

Ben Adida
(ben@adida.net)
"""

from django.db.models import permalink, signals
from google.appengine.ext import db

from django.utils import simplejson
import datetime, logging

from google.appengine.api import datastore_types

from crypto import electionalgs, algs, utils

from helios import utils as heliosutils

import helios

# counters
import counters

# useful stuff in auth
from auth.models import JSONProperty, User, AUTH_SYSTEMS
  
# global counters
GLOBAL_COUNTER_VOTERS = 'global_counter_voters'
GLOBAL_COUNTER_CAST_VOTES = 'global_counter_cast_votes'
GLOBAL_COUNTER_ELECTIONS = 'global_counter_elections'

# a counter incrementing function that is meant to run in a transaction
def __increment_counter(key, counter_name, amount):
  obj = db.get(key)
  new_value = getattr(obj, counter_name) + amount
  setattr(obj, counter_name, new_value)
  obj.put()
  return new_value
  
def increment_counter(key, counter_name, amount = 1):
  return db.run_in_transaction(__increment_counter, key, counter_name, amount)
  
class Election(db.Model, electionalgs.Election):
  admin = db.ReferenceProperty(User)
  
  uuid = db.StringProperty(multiline=False)
  
  short_name = db.StringProperty(multiline=False)
  name = db.StringProperty(multiline=False)
  description = db.TextProperty()
  public_key = JSONProperty(algs.EGPublicKey)
  private_key = JSONProperty(algs.EGSecretKey)
  questions = JSONProperty()
  
  # eligibility is a JSON field, which lists auth_systems and eligibility details for that auth_system, e.g.
  # [{'auth_system': 'cas', 'constraint': [{'year': 'u12'}, {'year':'u13'}]}, {'auth_system' : 'password'}, {'auth_system' : 'openid', 'constraint': [{'host':'http://myopenid.com'}]}]
  eligibility = JSONProperty()

  # types of ballot and tally
  # REMOVED 2009-11-19, we do choice_type and tally_type in the questions now
  #ballot_type = db.StringProperty(multiline=False)
  #tally_type = db.StringProperty(multiline=False)
  
  # open registration?
  # this is now used to indicate the state of registration,
  # whether or not the election is frozen
  openreg = db.BooleanProperty(default=False)
  
  # featured election?
  featured_p = db.BooleanProperty(default=False)
    
  # voter aliases?
  use_voter_aliases = db.BooleanProperty(default=False)
  
  # where votes should be cast
  cast_url = db.StringProperty(multiline=False)
  
  # dates at which things happen for the election
  frozen_at = db.DateTimeProperty(auto_now_add=False)
  archived_at = db.DateTimeProperty(auto_now_add=False, default=None)
  
  # dates to open up voting
  # these are always UTC
  voting_starts_at = db.DateTimeProperty(auto_now_add=False, default=None)
  voting_ends_at = db.DateTimeProperty(auto_now_add=False, default=None)

  # the hash of all voters (stored for large numbers)
  voters_hash = db.StringProperty(multiline=False)
  
  # encrypted tally, each a JSON string
  # used only for homomorphic tallies
  encrypted_tally = JSONProperty(electionalgs.Tally)

  # results of the election
  result = JSONProperty()

  # decryption proof, a JSON object
  result_proof = JSONProperty()
  
  # keep a bunch of counts
  num_voters = db.IntegerProperty(default = 0)
  num_cast_votes = db.IntegerProperty(default = 0)

  @classmethod
  def get_featured(cls):
    query = cls.all().filter('featured_p = ', True)
    return [e for e in query]
    
  @classmethod
  def get_or_create(cls, **kwargs):
    key_name = kwargs['short_name']
    obj = cls.get_by_key_name(key_name)
    created_p = False
    if not obj:
      created_p = True
      obj = cls(key_name = key_name, **kwargs)
      obj.put()
    return obj, created_p

  @classmethod
  def get_by_user_as_admin(cls, user, include_archived=False):
    query = cls.all()
    query.filter('admin =', user)
    if include_archived:
      query.filter('archived_at =', None)

    return [e for e in query]
    
  @classmethod
  def get_by_user_as_voter(cls, user):
    return [v.election for v in Voter.get_by_user(user)]
    
  @classmethod
  def get_by_uuid(cls, uuid):
    query = cls.all()
    query.filter('uuid = ', uuid)
    elections = query.fetch(1)
    
    if len(elections) > 0:
      return elections[0]
    else:
      return None
  
  @classmethod
  def get_by_short_name(cls, short_name):
    query = cls.all()
    query.filter('short_name = ', short_name)
    elections = query.fetch(1)
    
    if len(elections) > 0:
      return elections[0]
    else:
      return None
  
  def user_eligible_p(self, user):
    """
    Checks if a user is eligible for this election.
    """
    # registration closed, then eligibility doesn't come into play
    if not self.openreg:
      return False
    
    if self.eligibility == None:
      return False
      
    # is the user eligible for one of these cases?
    for eligibility_case in self.eligibility:
      if user.is_eligible_for(eligibility_case):
        return True
        
    return False
  
  def voting_has_started(self):
    return self.frozen_at != None and datetime.datetime.utcnow() >= self.voting_starts_at
    
  def voting_has_stopped(self):
    return datetime.datetime.utcnow() >= self.voting_ends_at or self.encrypted_tally
    
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
  
  def generate_voters_hash(self):
    """
    look up the list of voters, make a big file, and hash it
    FIXME: for more than 1000 voters, need to loop multiple times
    """
    if self.openreg:
      self.voters_hash = None
    else:
      voters = Voter.get_by_election(self)
      voters_json = utils.to_json([v.toJSONDict() for v in voters])
      self.voters_hash = utils.hash_b64(voters_json)
    
  def increment_voters(self):
    # increment global counter
    counters.increment(GLOBAL_COUNTER_VOTERS)

    return increment_counter(self.key(), 'num_voters')
    
  def increment_cast_votes(self):
    # increment global counter
    counters.increment(GLOBAL_COUNTER_CAST_VOTES)

    return increment_counter(self.key(), 'num_cast_votes')
    
  def put(self, *args, **kwargs):
    """
    override this just to get a hook
    """
    # not saved yet?
    increment_p = False
    if not self.is_saved():
      increment_p = True
      
    super(Election, self).put(*args, **kwargs)

    ## TRANSACTION PROBLEM, we won't increment here
    # do the increment afterwards in case of an exception which prevents the creation
    #if increment_p:
    #  counters.increment(GLOBAL_COUNTER_ELECTIONS)
    
    
  def freeze(self):
    self.frozen_at = datetime.datetime.utcnow()
    
    # voters hash
    self.generate_voters_hash()
    
    # public key for trustees
    trustees = Trustee.get_by_election(self)
    combined_pk = trustees[0].public_key
    for t in trustees[1:]:
      combined_pk = combined_pk * t.public_key
      
    self.public_key = combined_pk
    
    self.save()

  @property
  def url(self):
    return helios.get_election_url(self)
    
class Voter(db.Model, electionalgs.Voter):
  election = db.ReferenceProperty(Election)
  
  name = db.StringProperty(multiline=False)
  voter_type = db.StringProperty(multiline=False)
  voter_id = db.StringProperty(multiline=False)
  uuid = db.StringProperty(multiline=False)
  
  # if election uses aliases
  alias = db.StringProperty(multiline=False)
  
  # we keep a copy here for easy tallying
  vote = JSONProperty(electionalgs.EncryptedVote)
  vote_hash = db.StringProperty(multiline=False)
  cast_at = db.DateTimeProperty(auto_now_add=False)
  
  @classmethod
  def get_by_election(cls, election, cast=None, order_by='voter_id', after=None, limit=None):
    q = cls.all()
    q.filter('election =', election)
    
    # the boolean check is not stupid, this is ternary logic
    # none means don't care if it's cast or not
    if cast == True:
      q.filter('cast_at !=', None)
    elif cast == False:
      q.filter('cast_at =', None)

    # little trick to get around GAE limitation
    # order by uuid only when no inequality has been added
    if cast == None or order_by == 'cast_at' or order_by =='-cast_at':
      q.order(order_by)
      
      # if we want the list after a certain UUID, add the inequality here
      if after:
        if order_by[0] == '-':
          q.filter('%s >' % order_by[1:], after)
        else:
          q.filter('%s >' % order_by, after)
    
    if limit:
      return [v for v in q.fetch(limit)]
    else:
      return [v for v in q]

  @classmethod
  def get_all_by_election_in_chunks(cls, election, cast=None, chunk=100):
    voters = []
    after = None

    while True:
      new_voters = cls.get_by_election(election, cast=cast, after=after, limit=chunk)
      if len(new_voters) == 0:
        break
      voters += new_voters
      after = new_voters[-1].voter_id
    
    return voters
    
  @classmethod
  def get_by_election_and_user(cls, election, user):
    q = cls.all()
    q.filter('election = ', election)
    q.filter('voter_type = ', user.user_type)
    q.filter('voter_id = ', user.user_id)

    lst = q.fetch(1)
    if len(lst) > 0:
      return lst[0]
    else:
      return None
      
  @classmethod
  def get_by_election_and_uuid(cls, election, uuid):
    q = cls.all()
    q.filter('election = ', election)
    q.filter('uuid = ', uuid)

    lst = q.fetch(1)
    if len(lst) > 0:
      return lst[0]
    else:
      return None
  
  @classmethod
  def get_by_user(cls, user):
    q = cls.all()
    q.filter('voter_type = ', user.user_type)
    q.filter('voter_id = ', user.user_id)

    return [v for v in q]
  
  @property
  def user(self):
    return User.get_by_type_and_id(self.voter_type, self.voter_id)
    
  @property
  def election_uuid(self):
    return self.election.uuid
  
  def put(self, *args, **kwargs):
    """
    override this just to get a hook
    """
    # not saved yet?
    increment_p = False
    if not self.is_saved():
      increment_p = True
      
    super(Voter, self).put(*args, **kwargs)

    # do the increment afterwards in case of an exception which prevents the creation
    if increment_p:
      new_num_voters = self.election.increment_voters()
      if self.election.use_voter_aliases:
        self.alias = 'V' + str(new_num_voters)
        # recursive only once, at least it should be
        self.save()

  def store_vote(self, cast_vote):
    cast_vote.save()

    if self.cast_at == None:
      self.election.increment_cast_votes()

    self.vote = cast_vote.vote
    self.vote_hash = cast_vote.vote_hash
    self.cast_at = cast_vote.cast_at
    self.save()
  
  def last_cast_vote(self):
    return CastVote(vote = self.vote, vote_hash = self.vote_hash, cast_at = self.cast_at, voter=self)
    
  
class CastVote(db.Model, electionalgs.CastVote):
  # the reference to the voter provides the voter_uuid
  voter = db.ReferenceProperty(Voter)
  
  # a json array, which should contain election_uuid and election_hash
  vote = JSONProperty(electionalgs.EncryptedVote)

  # cache the hash of the vote
  vote_hash = db.StringProperty(multiline=False)

  cast_at = db.DateTimeProperty(auto_now_add=True)  
  
  @property
  def voter_uuid(self):
    return self.voter.uuid  
    
  @property
  def voter_hash(self):
    return self.voter.hash
  
  @classmethod
  def get_by_election_and_voter(cls, election, voter):
    q = cls.all()
    q.filter('voter = ', voter)
    q.order('-cast_at')
    return [v for v in q]
    
class OpenBallot(db.Model):
  """
  ballots for auditing
  """
  election = db.ReferenceProperty(Election)
  vote = JSONProperty(electionalgs.EncryptedVote)
  vote_hash = db.StringProperty(multiline=False)
  added_at = db.DateTimeProperty(auto_now_add=True)
    
class Trustee(db.Model, electionalgs.Trustee):
  election = db.ReferenceProperty(Election)
  
  uuid = db.StringProperty(multiline=False)
  name = db.StringProperty(multiline=False)
  email = db.EmailProperty()
  secret = db.StringProperty(multiline=False)
  
  # public key
  public_key = JSONProperty(algs.EGPublicKey)
  public_key_hash = db.StringProperty(multiline=False)
  
  # proof of knowledge of secret key
  pok = JSONProperty(algs.DLogProof)
  
  # decryption factors
  decryption_factors = JSONProperty()
  decryption_proofs = JSONProperty()
  
  def put(self, *args, **kwargs):
    """
    override this just to get a hook
    """
    # not saved yet?
    if not self.secret:
      self.secret = heliosutils.random_string(12)
      
    super(Trustee, self).put(*args, **kwargs)
  
  @classmethod
  def get_by_election(cls, election):
    q = cls.all()
    q.filter('election =', election)
    
    return [t for t in q]

  @classmethod
  def get_by_uuid(cls, uuid):
    q = cls.all()
    q.filter('uuid = ', uuid)
    return q.fetch(1)[0]
    
  @classmethod
  def get_by_election_and_uuid(cls, election, uuid):
    q = cls.all()
    q.filter('election =', election)
    q.filter('uuid = ', uuid)
    return q.fetch(1)[0]

  @classmethod
  def get_by_election_and_email(cls, election, email):
    q = cls.all()
    q.filter('election =', election)
    q.filter('email = ', email)
    return q.fetch(1)[0]
    
  def verify_decryption_proofs(self):
    """
    verify that the decryption proofs match the tally for the election
    """
    # verify_decryption_proofs(self, decryption_factors, decryption_proofs, public_key, challenge_generator):
    return self.election.encrypted_tally.verify_decryption_proofs(self.decryption_factors, self.decryption_proofs, self.public_key, algs.EG_fiatshamir_challenge_generator)
    
