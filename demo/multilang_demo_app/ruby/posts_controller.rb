class PostsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:publish]

  def search
    @posts = Post.where("title LIKE '%#{params[:q]}%'")
    render :index
  end

  def search_safe
    @posts = Post.where("title LIKE ?", "%#{params[:q]}%")
    render :index
  end

  def show_raw
    render html: "<article>#{Post.find(params[:id]).body}</article>".html_safe
  end

  def import
    settings = YAML.load(params[:payload])
    Settings.apply(settings)
    head :ok
  end

  def clock
    render plain: `date -d "#{params[:when]}"`
  end
end
