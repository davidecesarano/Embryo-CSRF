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
        private $sessionRequestAttribute = 'session';

        /**
         * @var array acceptMethods
         */
        private $allowMethods = ['DELETE', 'PATCH', 'POST', 'PUT'];

        /**
         * @var string $formKey
         */
        private $formInputName = 'csrf_token';

        /**
         * @var string $sessionKey
         */
        private $sessionKey = 'csrf_token';

        /**
         * @var int $limit
         */
        private $limit = 5;

        /**
         * @var array $except
         */
        private $except = [];

        /**
         * Set session request attribute.
         *
         * @param string $sessionAttribute
         * @return self
         */
        public function setSessionRequestAttribute(string $sessionRequestAttribute): self
        {
            $this->sessionRequestAttribute = $sessionRequestAttribute;
            return $this;
        }

        /**
         * Set form input name.
         *
         * @param string $formInputName
         * @return self
         */
        public function setFormInputName(string $formInputName): self
        {
            $this->formInputName = $formInputName;
            return $this;
        }

        /**
         * Set session key.
         *
         * @param string $sessionKey
         * @return self
         */
        public function setSessionKey(string $sessionKey): self
        {
            $this->sessionKey = $sessionKey;
            return $this;
        }

        /**
         * Set limit the number of token 
         * to store in the session.
         *
         * @param integer $limit
         * @return self
         */
        public function setLimit(int $limit): self 
        {
            $this->limit = $limit;
            return $this;
        }

        /**
         * Set uri exceptions.
         *
         * @param array $except
         * @return self
         */
        public function setExcept(array $except): self
        {
            $this->except = $except;
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
            if ($this->isExcept($request)) {
                return $handler->handle($request);
            }

            $session = $request->getAttribute($this->sessionRequestAttribute);
            if (in_array($request->getMethod(), $this->allowMethods, true)) {
                
                $params = $request->getParsedBody() ?: [];
                if (!array_key_exists($this->formInputName, $params)) {
                    throw new NoCsrfTokenException('CSRF token missing');
                }
                if (!in_array($params[$this->formInputName], $session->get($this->sessionKey, []), true)) {
                    throw new InvalidCsrfTokenException('Invalid CSRF token');
                }
                $this->removeToken($session, $params[$this->formInputName]);

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

        /**
         * Exclude uri from CSRF protection.
         *
         * @param ServerRequestInterface $request
         * @return bool
         */
        private function isExcept(ServerRequestInterface $request): bool
        {
            $path = trim($request->getUri()->getPath(), '/');
            if (!empty($this->except)) {
                foreach ($this->except as $except) {
                    $except = str_replace('*', '(.*)', $except);
                    $except = str_replace('/', '\/', $except);
                    $regex  = '/^'.$except.'$/';
                    if (preg_match($regex, $path)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }