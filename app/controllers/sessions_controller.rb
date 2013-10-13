class SessionsController < ApplicationController
  def new
    @user = User.new
    render :new
  end

  def create
    @user = User.find_by_credentials(params[:user][:email], params[:user][:password])

    if @user
      login_user(@user)
      flash[:notice] = "#{@user.name} signed in"
      redirect_to root_url
    else
      @user = User.new
      flash.now[:errors] = ["Email or password invalid"]
      render :new
    end
  end

  def destroy
    current_user.reset_session_token!
    session[:session_token] = nil

    redirect_to new_session_url
  end
end
