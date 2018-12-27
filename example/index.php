<?php 
    
    require __DIR__ . '/../vendor/autoload.php';
    
    use Embryo\CSRF\CsrfMiddleware;
    use Embryo\Http\Emitter\Emitter;
    use Embryo\Http\Server\MiddlewareDispatcher;
    use Embryo\Http\Factory\{ServerRequestFactory, ResponseFactory};
    use Embryo\Session\Session;
    use Embryo\Session\Middleware\SessionMiddleware;
    use Psr\Http\Message\ResponseInterface;
    use Psr\Http\Message\ServerRequestInterface;
    use Psr\Http\Server\MiddlewareInterface;
    use Psr\Http\Server\RequestHandlerInterface;

    $request    = (new ServerRequestFactory)->createServerRequestFromServer();
    $response   = (new ResponseFactory)->createResponse();
    $session    = new Session;
    $middleware = new MiddlewareDispatcher;

    class GenerateInputMiddleware implements MiddlewareInterface
    {
        public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
        {
            $response = $handler->handle($request);
            $session  = $request->getAttribute('session');
            $token    = $session->get('csrf_token');
            return $response->write('<input type="hidden" name="csrf_token" value="'.end($token).'">');
        }
    }

    $middleware->add(
        (new SessionMiddleware)
            ->setSession($session)
            ->setOptions([
                'use_cookies'      => false,
                'use_only_cookies' => true
            ])
    );
    $middleware->add(CsrfMiddleware::class);
    $middleware->add(GenerateInputMiddleware::class);
    $response = $middleware->dispatch($request, $response);

    $emitter = new Emitter;
    $emitter->emit($response);