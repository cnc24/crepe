(component
  (core module $m
    (memory (export "memory") 2)
    (data (i32.const 16) "\7b\22\6d\65\73\73\61\67\65\22\3a\22\45\78\61\6d\70\6c\65\20\70\6c\75\67\69\6e\20\6f\62\73\65\72\76\61\74\69\6f\6e\22\7d")
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const 1024)
    (func (export "process") (param i32 i32) (result i32)
      i32.const 0 i32.const 16 i32.store
      i32.const 4 i32.const 40 i32.store
      i32.const 0))
  (core instance $i (instantiate $m))
  (func (export "process") (param "event" string) (result string)
    (canon lift (core func $i "process")
      (memory (core memory $i "memory"))
      (realloc (core func $i "realloc")))))
