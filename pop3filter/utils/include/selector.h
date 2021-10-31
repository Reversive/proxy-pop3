#ifndef SELECTOR_H_W50GNLODsARolpHbsDsrvYvMsbT
#define SELECTOR_H_W50GNLODsARolpHbsDsrvYvMsbT

#include <sys/time.h>
#include <stdbool.h>
#include <stdio.h>
/**
 * selector.c - un muliplexor de entrada salida
 *
 * Un selector permite manejar en un Ãºnico hilo de ejecuciÃ³n la entrada salida
 * de file descriptors de forma no bloqueante.
 *
 * Esconde la implementaciÃ³n final (select(2) / poll(2) / epoll(2) / ..)
 *
 * El usuario registra para un file descriptor especificando:
 *  1. un handler: provee funciones callback que manejarÃ¡n los eventos de
 *     entrada/salida
 *  2. un interÃ©s: que especifica si interesa leer o escribir.
 *
 * Es importante que los handlers no ejecute tareas bloqueantes ya que demorarÃ¡
 * el procesamiento del resto de los descriptores.
 *
 * Si el handler requiere bloquearse por alguna razÃ³n (por ejemplo realizar
 * una resoluciÃ³n de DNS utilizando getaddrinfo(3)), tiene la posiblidad de
 * descargar el trabajo en un hilo notificarÃ¡ al selector que el resultado del
 * trabajo estÃ¡ disponible y se le presentarÃ¡ a los handlers durante
 * la iteraciÃ³n normal. Los handlers no se tienen que preocupar por la
 * concurrencia.
 *
 * Dicha seÃ±alizaciÃ³n se realiza mediante seÃ±ales, y es por eso que al
 * iniciar la librerÃ­a `selector_init' se debe configurar una seÃ±al a utilizar.
 *
 * Todos mÃ©todos retornan su estado (Ã©xito / error) de forma uniforme.
 * Puede utilizar `selector_error' para obtener una representaciÃ³n human
 * del estado. Si el valor es `SELECTOR_IO' puede obtener informaciÃ³n adicional
 * en errno(3).
 *
 * El flujo de utilizaciÃ³n de la librerÃ­a es:
 *  - iniciar la libreria `selector_init'
 *  - crear un selector: `selector_new'
 *  - registrar un file descriptor: `selector_register_fd'
 *  - esperar algÃºn evento: `selector_iteratate'
 *  - destruir los recursos de la librerÃ­a `selector_close'
 */
typedef struct fdselector * fd_selector;

/** valores de retorno. */
typedef enum {
    /** llamada exitosa */
    SELECTOR_SUCCESS  = 0,
    /** no pudimos alocar memoria */
    SELECTOR_ENOMEM   = 1,
    /** llegamos al lÃ­mite de descriptores que la plataforma puede manejar */
    SELECTOR_MAXFD    = 2,
    /** argumento ilegal */
    SELECTOR_IARGS    = 3,
    /** descriptor ya estÃ¡ en uso */
    SELECTOR_FDINUSE  = 4,
    /** I/O error check errno */
    SELECTOR_IO       = 5,
} selector_status;

/** retorna una descripciÃ³n humana del fallo */
const char *
selector_error(const selector_status status);

/** opciones de inicializaciÃ³n del selector */
struct selector_init {
    /** seÃ±al a utilizar para notificaciones internas */
    const int signal;

    /** tiempo mÃ¡ximo de bloqueo durante `selector_iteratate' */
    struct timespec select_timeout;
};

/** inicializa la librerÃ­a */
selector_status
selector_init(const struct selector_init *c);

/** deshace la incializaciÃ³n de la librerÃ­a */
selector_status
selector_close(void);

/* instancia un nuevo selector. returna NULL si no puede instanciar  */
fd_selector
selector_new(const size_t initial_elements);

/** destruye un selector creado por _new. Tolera NULLs */
void
selector_destroy(fd_selector s);

/**
 * Intereses sobre un file descriptor (quiero leer, quiero escribir, â€¦)
 *
 * Son potencias de 2, por lo que se puede requerir una conjunciÃ³n usando el OR
 * de bits.
 *
 * OP_NOOP es Ãºtil para cuando no se tiene ningÃºn interÃ©s.
 */
typedef enum {
    OP_NOOP    = 0,
    OP_READ    = 1 << 0,
    OP_WRITE   = 1 << 2,
} fd_interest ;

/**
 * Quita un interÃ©s de una lista de intereses
 */
#define INTEREST_OFF(FLAG, MASK)  ( (FLAG) & ~(MASK) )

/**
 * Argumento de todas las funciones callback del handler
 */
struct selector_key {
    /** el selector que dispara el evento */
    fd_selector s;
    /** el file descriptor en cuestion */
    int         fd;
    /** dato provisto por el usuario */
    void *      data;
};

/**
 * Manejador de los diferentes eventos..
 */
typedef struct fd_handler {
  void (*handle_read)      (struct selector_key *key);
  void (*handle_write)     (struct selector_key *key);
  void (*handle_block)     (struct selector_key *key);

  /**
   * llamado cuando se se desregistra el fd
   * Seguramente deba liberar los recusos alocados en data.
   */
  void (*handle_close)     (struct selector_key *key);

} fd_handler;

/**
 * registra en el selector `s' un nuevo file descriptor `fd'.
 *
 * Se especifica un `interest' inicial, y se pasa handler que manejarÃ¡
 * los diferentes eventos. `data' es un adjunto que se pasa a todos
 * los manejadores de eventos.
 *
 * No se puede registrar dos veces un mismo fd.
 *
 * @return 0 si fue exitoso el registro.
 */
selector_status
selector_register(fd_selector        s,
                  const int          fd,
                  const fd_handler  *handler,
                  const fd_interest  interest,
                  void *data);

/**
 * desregistra un file descriptor del selector
 */
selector_status
selector_unregister_fd(fd_selector   s,
                       const int     fd);

/** permite cambiar los intereses para un file descriptor */
selector_status
selector_set_interest(fd_selector s, int fd, fd_interest i);

/** permite cambiar los intereses para un file descriptor */
selector_status
selector_set_interest_key(struct selector_key *key, fd_interest i);


/**
 * se bloquea hasta que hay eventos disponible y los despacha.
 * Retorna luego de cada iteraciÃ³n, o al llegar al timeout.
 */
selector_status
selector_select(fd_selector s);

/**
 * MÃ©todo de utilidad que activa O_NONBLOCK en un fd.
 *
 * retorna -1 ante error, y deja detalles en errno.
 */
int
selector_fd_set_nio(const int fd);

/** notifica que un trabajo bloqueante terminÃ³ */
selector_status
selector_notify_block(fd_selector s,
                 const int   fd);

#endif