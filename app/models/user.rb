class User < ActiveRecord::Base
  attr_reader :password

  before_validation { self.session_token ||= self.class.generate_session_token }

  validates :email, :first_name, :last_name, :presence => true
  validates :password, :presence => { :minimum => 6, :allow_nil => true }
  validates :password_digest, :presence => { :message => "Password cannot be empty" }


  def self.find_by_credentials(username, password)
    user = self.find_by_email(username)

    return nil unless user

    user.is_password?(password) ? user : nil
  end

  def self.generate_session_token
    SecureRandom.urlsafe_base64(16)
  end

  def reset_session_token!
    self.session_token = self.class.generate_session_token
    self.save!
  end

  def password=(password)
    self.password_digest = BCrypt::Password.create(password)
  end

  def is_password?(password)
    BCrypt::Password.new(self.password_digest).is_password?(password)
  end

  def name
    "#{self.first_name} #{self.last_name}"
  end
end
