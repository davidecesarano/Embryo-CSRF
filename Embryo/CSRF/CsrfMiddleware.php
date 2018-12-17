<?php 
    
    /**
     * CsrfMiddleware
     * 
     * A PSR-15 compatible middleware to prevent CSRF.
     * 
     * @author Davide Cesarano <davide.cesarano@unipegaso.it>
     * @link   https://github.com/davidecesarano/embryo-csrf
     */

    namespace Embryo\CSRF;
    
    use Embryo\Session\Session;
    use Embryo\CSRF\Exceptions\{InvalidCsrfTokenException, NoCsrfTokenException};
    use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};
    use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};
    
    class CsrfMiddleware implements MiddlewareInterface 
    {   
        /**
         * @var string sessionAttribute
         */
        private $sessionAttribute = 'session';

        /**
         * @var array acceptMethods
         */
        private $allowMethods = ['DELETE', 'PATCH', 'POST', 'PUT'];

        /**
         * @var string $formKey
         */
        private $formKey = 'csrf_token';

        /**
         * @var string $sessionKey
         */
        private $sessionKey = 'csrf_token';

        /**
         * @var int $limit
         */
        private $limit = 5;

        public function setSessionAttribute(string $sessionAttribute): self
        {
            $this->sessionAttribute = $sessionAttribute;
            return $this;
        }

        public function setFormKey(string $formKey): self
        {
            $this->formKey = $formKey;
            return $this;
        }

        public function setSessionKey(string $sessionKey): self
        {
            $this->sessionKey = $sessionKey;
            return $this;
        }

        /**
         * Process a server request and return a response.
         *
         * @param ServerRequestInterface $request
         * @param RequestHandlerInterface $handler
         * @return ResponseInterface
         * @throws NoCsrfTokenException
         * @throws InvalidCsrfTokenException
         */
        public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
        {
            $session = $request->getAttribute($this->sessionAttribute);

            if (in_array($request->getMethod(), $this->allowMethods, true)) {
                
                $params = $request->getParsedBody() ?: [];
                if (!array_key_exists($this->formKey, $params)) {
                    throw new NoCsrfTokenException('CSRF token missing');
                }
                if (!in_array($params[$this->formKey], $session->get($this->sessionKey, []), true)) {
                    throw new InvalidCsrfTokenException('Invalid CSRF token');
                }
                $this->removeToken($session, $params[$this->formKey]);

            } else {
                $this->generateToken($session);
            }
            return $handler->handle($request);
        }

        /**
         * Generate CSRF Token.
         *
         * @param Session $session
         * @return void
         */
        private function generateToken(Session $session): void
        {
            $token  = bin2hex(random_bytes(16));
            $tokens = $session->get($this->sessionKey, []);
            
            $tokens[] = $token;
            if (count($tokens) > $this->limit) {
                array_shift($tokens);
            }
            
            $session->set($this->sessionKey, $tokens);
        }

        /**
         * Remove CSRF Token.
         *
         * @param Session $session
         * @param string $token
         * @return void
         */
        private function removeToken(Session $session, string $token): void
        {
            $tokens = array_filter(
                $session->get($this->sessionKey, []),
                function ($t) use ($token) {
                    return $token !== $t;
                }
            );

            $session->set($this->sessionKey, $tokens);
        }
    }