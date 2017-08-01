class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
         :omniauthable, :omniauth_providers => [:facebook]
def self.from_omniauth(auth)
        user = User.where(provider: auth.provider, uid: auth.uid).first
        if user.present?
            user
        else
            user = User.create!(
                                                 provider:auth.provider,
                                                 uid:auth.uid,
                                                 email:auth.info.email,
                                                 password:Devise.friendly_token[0,20])
        end
    end
  
  
  
end