class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  validates :age, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
  has_many :ideas
  ROLES = %w[admin user]
end
