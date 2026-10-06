# One configuration file per framework, and one trap

A project nobody would ship: Symfony, Laravel, CodeIgniter and Yii configuration
side by side, so one scan covers every shape the configuration detectors read —
plus one Laravel controller, because a call site and a configuration line are two
different facts. The configuration says which cipher; the controller says how many
places depend on it.

The trap is in `config/packages/framework.yaml`: `cookie_secure: auto`. `auto` is
also the name of a Symfony password hasher, and the first version of the shorthand
pattern reported a password hasher that does not exist — in a real application,
not in a fixture. The file deliberately does not declare `password_hashers`, so a
detector that reads it as one has lost its context.
