<?php

/**
 * Bit Points Network
 * Copyright (C) 2021  Nikita Podvirnyy

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 * Contacts:
 *
 * Email: <suimin.tu.mu.ga.mi@gmail.com>
 * GitHub: https://github.com/KRypt0nn
 * VK:     https://vk.com/technomindlp
 */

namespace BPN;

spl_autoload_register (function (string $class)
{
    if (strlen ($class) > 3 && file_exists ($class = __DIR__ .'/src'. str_replace ('\\', '/', substr ($class, 3)) .'.php'))
        require $class;
});
