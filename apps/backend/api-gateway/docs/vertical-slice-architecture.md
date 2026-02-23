# Vertical Slice Architecture

```
src/
  modules/
    user/
      _shared/
        domain/
          common/
            base-entity.ts
            domain-event.ts
            domain-error.ts

          user/
            user.entity.ts
            user.errors.ts
            user.events.ts
            user.value-objects.ts

          session/
            session.entity.ts
            session.events.ts

        persistence/
          write/
            user/
              user.repository.port.ts
              drizzle-user.repository.ts
              user.mapper.ts
              user.model.ts

            session/
              session.repository.port.ts
              drizzle-session.repository.ts
              session.model.ts

          read/
            user/
              user.query-builder.port.ts
              drizzle-user.query-builder.ts
              user.read-model.ts

        services/
          user.service.interface.ts
          user.service.ts

      commands/
        create-user/
          usecase.ts
          handler.ts
          schema.ts
          test.ts

        update-user/
          usecase.ts
          handler.ts

      queries/
        get-user/
          query.ts
          handler.ts
          schema.ts
          test.ts

        list-users/
          query.ts
          handler.ts

      events/
        send-welcome-email.handler.ts
        create-default-session.handler.ts
```
