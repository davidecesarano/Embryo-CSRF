# Embryo CSRF
A PSR-15 compatible middleware to prevent CSRF. This middleware checks every POST, PATCH, PUT and DELETE requests for a CSRF token. The token is stored in session request attribute.

## Requirements
* PHP >= 7.1
* A [PSR-7](https://www.php-fig.org/psr/psr-7/) http message implementation and [PSR-17](https://www.php-fig.org/psr/psr-17/) http factory implementation (ex. [Embryo-Http](https://github.com/davidecesarano/Embryo-Http))
* A [PSR-15](https://www.php-fig.org/psr/psr-15/) http server request handlers implementation (ex. [Embryo-Middleware](https://github.com/davidecesarano/Embryo-Middleware))
* A PSR-15 session middleware (Ex. [Embryo-Session](https://github.com/davidecesarano/Embryo-Session))
* A PSR response emitter (ex. [Embryo-Emitter](https://github.com/davidecesarano/Embryo-Emitter))

## Installation
Using Composer:
```
$ composer require davidecesarano/embryo-csrf
```

## Usage
Add `Embryo\CSRF\CsrfMiddleware` to middleware dispatcher:
```php
use Embryo\Http\Emitter\Emitter;
use Embryo\Http\Server\MiddlewareDispatcher;
use Embryo\Http\Factory\{ServerRequestFactory, ResponseFactory};
use Embryo\CSRF\CsrfMiddleware;

$request    = (new ServerRequestFactory)->createServerRequestFromServer();
$response   = (new ResponseFactory)->createResponse();
$session    = new Session;
$middleware = new MiddlewareDispatcher;

// example: generate form input
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

// SessionMiddleware
$middleware->add(
    (new SessionMiddleware)
        ->setSession($session)
        ->setOptions([
            'use_cookies'      => false,
            'use_only_cookies' => true
        ])
);

// CsrfMiddleware
$middleware->add(CsrfMiddleware::class);

// GenerateInputMiddleware
$middleware->add(GenerateInputMiddleware::class);

$response = $middleware->dispatch($request, $response);
$emitter = new Emitter;
$emitter->emit($response);
```
You may quickly test this using the built-in PHP server going to http://localhost:8000.

```
$ cd example
$ php -S localhost:8000
```

## Options
### `setSessionRequestAttribute(string $sessionRequestAttribute)`
Set session request attribute. If it's not provided, use `$request->getAttribute('session')`.
### `setFormInputName(string $formInputName)`
Set the form input name. If it's not provided, use `csrf_token`.
### `setSessionKey(string $sessionKey)`
Set the session key. If it's not provided, use `$session->get('csrf_token')`.
### `setLimit(int $limit)`
Set limit the number of token to store in the session. If it's not provided, is `5`.