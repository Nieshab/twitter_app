class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

mount_uploader :avatar, AvatarUploader
         has_many :tweets

          validates :username, presence: true, uniqueness: true
# this is where the array that contains everyone you are following in
          serialize :following, Array



end
