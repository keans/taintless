class Animal {
public:
    virtual void speak() {}
    void twice() { this->speak(); }
};

class Cat : public Animal {
public:
    void speak() override {}
};
