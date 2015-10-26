from pyramid.config import Configurator

from pyramid_jwtauth import includeme

from pyramid.security import Allow, Everyone
from pyramid.httpexceptions import HTTPUnauthorized

class RootFactory(object):
    __name__ = 'RootFactory'
    __acl__ = [ (Allow, Everyone, 'view'),
                (Allow, 'group:editors', 'edit')
            ]
    def __init__(self, request):
        pass

def jwt_database_validation_tween_factory(handler, registry):
    # Check the validity of the received token
    # Should be run after the cookie to authorization tween.

    def tween(request):
        if request.authorization is None:
            # Skipping validation if there is no authorization object.
            # This is dangerous since a bad ordering of this tween and the
            # cookie tween would bypass security
            return handler(request)
        else:
            # Skip the token=" prefix and " suffix
            token = request.authorization[1][7:-1]
            print(token)
    
            # Simulate database interaction by requiring token to end with Q
            valid = token.endswith("Q")
    
            if valid:
                return handler(request)
            else:
                return HTTPUnauthorized("Bad token") # TODO: clear cookie?

    return tween

def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.include('pyramid_chameleon')

    config.add_tween('api.jwt_database_validation_tween_factory')

    config.include("pyramid_jwtauth")
    config.set_root_factory(RootFactory)

    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_route('protected', '/protected')
    config.add_route('login', '/login')
    config.scan()
    return config.make_wsgi_app()
