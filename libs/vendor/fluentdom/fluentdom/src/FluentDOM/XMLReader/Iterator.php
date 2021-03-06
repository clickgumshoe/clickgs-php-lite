<?php
namespace FluentDOM\XMLReader {

  use FluentDOM\XMLReader;

  /**
   * Class Iterator
   *
   * It will use XMLReader::read() to iterate the nodes and use expand to return each found node as DOM node.
   */
  class Iterator implements \Iterator {

    /**
     * @var XMLReader
     */
    private $_reader;
    /**
     * @var string|null
     */
    private $_name;
    /**
     * @var callable
     */
    private $_filter;

    /**
     * @var integer
     */
    private $_key = -1;

    /**
     * @var null|\DOMNode
     */
    private $_current = NULL;

    /**
     * Iterator constructor.
     *
     * @param XMLReader $reader
     * @param null $name tag name
     * @param callable|NULL $filter
     */
    public function __construct(
      XMLReader $reader, $name = NULL, callable $filter = NULL
    ) {
      $this->_reader = $reader;
      $this->_name = $name;
      $this->_filter = $filter;
    }

    /**
     * Throw an exception if rewind() is called after next()
     */
    public function rewind() {
      if ($this->_key >= 0) {
        throw new \LogicException(sprintf('%s is not a seekable iterator', __CLASS__));
      }
      $this->next();
    }

    public function next() {
      if ($this->move($this->_reader, $this->_name, $this->_filter)) {
        $this->_current = (NULL === $this->_current)
          ? $this->_reader->expand()
          : $this->_reader->expand($this->_current->ownerDocument);
        $this->_key++;
      } else {
        $this->_current = NULL;
      }
    }

    protected function move(XMLReader $reader, $name, $filter) {
      return $reader->read($name, NULL, $filter);
    }

    /**
     * @return bool
     */
    public function valid() {
      return NULL !== $this->_current;
    }

    /**
     * @return \DOMNode|null
     */
    public function current() {
      return $this->_current;
    }

    /**
     * @return int
     */
    public function key() {
      return $this->_key;
    }
  }
}
