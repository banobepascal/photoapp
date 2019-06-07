jQuery(document).ready(function () {

    var ua = navigator.userAgent.toLowerCase();
    if ((ua.indexOf("safari/") !== -1 && ua.indexOf("windows") !== -1 && ua.indexOf("chrom") === -1) || is_touch_device())
    {
        jQuery("html").css('overflow', 'auto');

        jQuery('.post-num-comments a').click(function (e) {
            e.preventDefault();
            jQuery('html, body').animate({scrollTop: jQuery(this.hash).offset().top}, 2000);
            return false;
        });
    } else
    {
        jQuery("html").niceScroll({cursorcolor: "#b1b1b1", scrollspeed: 100, mousescrollstep: 80, cursorwidth: "12px", cursorborder: "none", cursorborderradius: "0px"});

        //Smooth scroll on single post (comments)
        jQuery('.post-num-comments a').click(function (e) {
            e.preventDefault();
            jQuery("html").getNiceScroll(0).doScrollTop(jQuery(this.hash).offset().top);
        });
    }

    jQuery(".site-content").fitVids();


    //Add before and after "blockquote" custom class
    jQuery('blockquote.inline-blockquote').prev('p').addClass('wrap-blockquote');
    jQuery('blockquote.inline-blockquote').next('p').addClass('wrap-blockquote');
    jQuery('blockquote.inline-blockquote').css('display', 'table');

    //Placeholder show/hide
    jQuery('input, textarea').focus(function () {
        jQuery(this).data('placeholder', jQuery(this).attr('placeholder'));
        jQuery(this).attr('placeholder', '');
    });
    jQuery('input, textarea').blur(function () {
        jQuery(this).attr('placeholder', jQuery(this).data('placeholder'));
    });

    //Portfolio

    var grid = jQuery('.grid').imagesLoaded(function () {
        grid.isotope({
            itemSelector: '.grid-item',
            masonry: {
                columnWidth: '.grid-sizer'
            }
        });

        // bind filter button click
        jQuery('.filters-button-group').on('click', '.button', function () {
            var filterValue = jQuery(this).attr('data-filter');
            grid.isotope({filter: filterValue});
            grid.on('arrangeComplete', function () {
                jQuery(".grid-item:visible a[rel^='prettyPhoto']").prettyPhoto({
                    slideshow: false, /* false OR interval time in ms */
                    overlay_gallery: false, /* If set to true, a gallery will overlay the fullscreen image on mouse over */
                    default_width: 1280,
                    default_height: 720,
                    deeplinking: false,
                    social_tools: false,
                    iframe_markup: '<iframe src ="{path}" width="{width}" height="{height}" frameborder="no" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe>',
                    changepicturecallback: function () {
                        if (!is_touch_device()) {
                            var ua = navigator.userAgent.toLowerCase();
                            if (!(ua.indexOf("safari/") !== -1 && ua.indexOf("windows") !== -1 && ua.indexOf("chrom") === -1))
                            {
                                jQuery("html").getNiceScroll().remove();
                                jQuery("html").css("cssText", "overflow: hidden !important");
                            }
                        }
                    },
                    callback: function () {
                        if (!is_touch_device()) {
                            var ua = navigator.userAgent.toLowerCase();
                            if (!(ua.indexOf("safari/") !== -1 && ua.indexOf("windows") !== -1 && ua.indexOf("chrom") === -1))
                            {
                                jQuery("html").niceScroll({cursorcolor: "#b1b1b1", scrollspeed: 100, mousescrollstep: 80, cursorwidth: "12px", cursorborder: "none", cursorborderradius: "0px"});
                            }
                        }
                    }
                });

            });
        });


        // change is-checked class on buttons
        jQuery('.button-group').each(function (i, buttonGroup) {
            var $buttonGroup = jQuery(buttonGroup);
            $buttonGroup.on('click', '.button', function () {
                $buttonGroup.find('.is-checked').removeClass('is-checked');
                jQuery(this).addClass('is-checked');
            });
        });


        //Fix for portfolio item text
        jQuery('.portfolio-text-holder').each(function () {
            jQuery(this).find('p').css('margin-top', jQuery(this).height() / 2);
        });

        //Fix for portfolio hover text fade in/out
        jQuery('.grid-item a').hover(function () {
            jQuery(this).find('.portfolio-text-holder').fadeIn('fast');
        }, function () {
            jQuery(this).find('.portfolio-text-holder').fadeOut('fast');
        });
    });


    //Fix for default menu
    jQuery('.default-menu ul').addClass('main-menu sm sm-clean');

});



jQuery(window).load(function () {

//Fix for header menu
    jQuery('.header-search').css('margin-top', 0 - jQuery('.header-search').innerHeight());

//Set menu
    jQuery('.main-menu').smartmenus({
        subMenusSubOffsetX: 1,
        subMenusSubOffsetY: -8,
        markCurrentItem: true
    });

    var $mainMenu = jQuery('.main-menu').on('click', 'span.sub-arrow', function (e) {
        var obj = $mainMenu.data('smartmenus');
        if (obj.isCollapsible()) {
            var $item = jQuery(this).parent(),
                    $sub = $item.parent().dataSM('sub');
            $sub.dataSM('arrowClicked', true);
        }
    }).bind({
        'beforeshow.smapi': function (e, menu) {
            var obj = $mainMenu.data('smartmenus');
            if (obj.isCollapsible()) {
                var $menu = jQuery(menu);
                if (!$menu.dataSM('arrowClicked')) {
                    return false;
                }
                $menu.removeDataSM('arrowClicked');
            }
        }
    });


//Show-Hide header sidebar
    jQuery('#toggle, .header-hidden-search a').on("click", multiClickFunctionStop);

//Set each image slider
    jQuery(".image-slider").each(function () {
        var id = jQuery(this).attr('id');
        if (window[id + '_pagination'] == 'true')
        {
            var pagination_value = '.' + id + '_pagination';
        } else
        {
            var pagination_value = false;
        }

        var auto_value = window[id + '_auto'];
        if (auto_value == 'false')
        {
            auto_value = false;
        } else {
            auto_value = true;
        }

        var hover_pause = window[id + '_hover'];
        if (hover_pause == 'true')
        {
            hover_pause = 'resume';
        } else {
            hover_pause = false;
        }

        var speed_value = window[id + '_speed'];

        jQuery('#' + id).carouFredSel({
            responsive: true,
            width: 'variable',
            auto: {
                play: auto_value,
                pauseOnHover: hover_pause
            },
            pagination: pagination_value,
            scroll: {
                fx: 'crossfade',
                duration: parseFloat(speed_value)
            },
            swipe: {
                onMouse: true,
                onTouch: true
            },
            items: {
                height: 'variable'
            }
        });
    });

    jQuery('.image-slider-wrapper').each(function () {
        var slider_width = jQuery(this).width();
        var pagination_width = jQuery(this).find('.carousel_pagination').width();
        jQuery(this).find('.carousel_pagination').css("margin-left", (slider_width - pagination_width) / 2);
    });


    //PrettyPhoto initial
    jQuery('a[data-rel]').each(function () {
        jQuery(this).attr('rel', jQuery(this).data('rel'));
    });

    jQuery("a[rel^='prettyPhoto']").prettyPhoto({
        slideshow: false, /* false OR interval time in ms */
        overlay_gallery: false, /* If set to true, a gallery will overlay the fullscreen image on mouse over */
        default_width: 1280,
        default_height: 720,
        deeplinking: false,
        social_tools: false,
        iframe_markup: '<iframe src ="{path}" width="{width}" height="{height}" frameborder="no" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe>',
        changepicturecallback: function () {
            if (!is_touch_device()) {
                var ua = navigator.userAgent.toLowerCase();
                if (!(ua.indexOf("safari/") !== -1 && ua.indexOf("windows") !== -1 && ua.indexOf("chrom") === -1))
                {
                    jQuery("html").getNiceScroll().remove();
                    jQuery("html").css("cssText", "overflow: hidden !important");
                }
            }
        },
        callback: function () {
            if (!is_touch_device()) {
                var ua = navigator.userAgent.toLowerCase();
                if (!(ua.indexOf("safari/") !== -1 && ua.indexOf("windows") !== -1 && ua.indexOf("chrom") === -1))
                {
                    jQuery("html").niceScroll({cursorcolor: "#b1b1b1", scrollspeed: 100, mousescrollstep: 80, cursorwidth: "12px", cursorborder: "none", cursorborderradius: "0px"});
                }
            }
        }
    });


    contactFormWidthFix();

    //Fix for post opacity
    jQuery(".blog-item-holder, .post-border").css({opacity: 1});

    jQuery('.doc-loader').fadeOut('fast');

});


jQuery(window).resize(function () {
    jQuery('.image-slider-wrapper').each(function () {
        var slider_width = jQuery(this).width();
        var pagination_width = jQuery(this).find('.carousel_pagination').width();
        jQuery(this).find('.carousel_pagination').css("margin-left", (slider_width - pagination_width) / 2);
    });


    //Fix for header menu
    if (!jQuery('.header-search').hasClass("open")) {
        jQuery('.header-search').css('margin-top', 0 - jQuery('.header-search').innerHeight());
    }

    //Fix for WP menu admin bar 
    jQuery('#main-menu').css('margin-top', jQuery('#wpadminbar').height());


    contactFormWidthFix();

    //Fix for portfolio item text
    jQuery('.portfolio-text-holder').each(function () {
        jQuery(this).find('p').css('margin-top', jQuery(this).height() / 2);
    });

});

//------------------------------------------------------------------------
//Helper Methods -->
//------------------------------------------------------------------------


var contactFormWidthFix = function () {
    jQuery('.wpcf7 input[type=text], .wpcf7 input[type=email], .wpcf7 textarea').innerWidth(jQuery('.wpcf7-form').width());
};

var multiClickFunctionStop = function (e) {
    e.preventDefault();
    jQuery('#toggle, .header-hidden-search a').off("click");
    jQuery('#toggle, .header-hidden-search a').toggleClass("on");
    if (jQuery('#toggle, .header-hidden-search a').hasClass("on"))
    {
        jQuery('html, body').animate({scrollTop: 0}, 200);

        jQuery('.header-search').addClass('open').animate({'marginTop': '0'}, function () {
            jQuery('#toggle, .header-hidden-search a').on("click", multiClickFunctionStop);
        });
    } else
    {
        jQuery('.header-search').removeClass('open').animate({'marginTop': 0 - jQuery('.header-search').innerHeight()}, function () {
            jQuery('#toggle, .header-hidden-search a').on("click", multiClickFunctionStop);
        });
    }

};

function is_touch_device() {
    return !!('ontouchstart' in window);
}

function isValidEmailAddress(emailAddress) {
    var pattern = /^([a-z\d!#$%&'*+\-\/=?^_`{|}~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]+(\.[a-z\d!#$%&'*+\-\/=?^_`{|}~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]+)*|"((([ \t]*\r\n)?[ \t]+)?([\x01-\x08\x0b\x0c\x0e-\x1f\x7f\x21\x23-\x5b\x5d-\x7e\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]|\\[\x01-\x09\x0b\x0c\x0d-\x7f\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))*(([ \t]*\r\n)?[ \t]+)?")@(([a-z\d\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]|[a-z\d\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF][a-z\d\-._~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]*[a-z\d\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])\.)+([a-z\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]|[a-z\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF][a-z\d\-._~\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]*[a-z\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])\.?$/i;
    return pattern.test(emailAddress);
}

var SendMail = function () {

    var emailVal = jQuery('#contact-email').val();

    if (isValidEmailAddress(emailVal)) {
        var params = {
            'action': 'SendMessage',
            'name': jQuery('#name').val(),
            'email': jQuery('#contact-email').val(),
            'subject': jQuery('#subject').val(),
            'message': jQuery('#message').val()
        };
        jQuery.ajax({
            type: "POST",
            url: "php/sendMail.php",
            data: params,
            success: function (response) {
                if (response) {
                    var responseObj = jQuery.parseJSON(response);
                    if (responseObj.ResponseData)
                    {
                        alert(responseObj.ResponseData);
                    }
                }
            },
            error: function (xhr, ajaxOptions, thrownError) {
                //xhr.status : 404, 303, 501...
                var error = null;
                switch (xhr.status)
                {
                    case "301":
                        error = "Redirection Error!";
                        break;
                    case "307":
                        error = "Error, temporary server redirection!";
                        break;
                    case "400":
                        error = "Bad request!";
                        break;
                    case "404":
                        error = "Page not found!";
                        break;
                    case "500":
                        error = "Server is currently unavailable!";
                        break;
                    default:
                        error = "Unespected error, please try again later.";
                }
                if (error) {
                    alert(error);
                }
            }
        });
    } else
    {
        alert('Your email is not in valid format');
    }
};